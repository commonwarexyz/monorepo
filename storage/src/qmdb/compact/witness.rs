//! Shared machinery for the compact-db witness journal.
//!
//! The witness journal is the single durable source of truth for a compact database. Each
//! [`Witness`] is a complete snapshot of one applied state: the commit operation, the committed
//! size, and the pinned nodes one operation below it. The commit's inclusion proof is not
//! stored. It is derived from the pinned nodes and the operation when an entry is loaded. On open
//! and rewind, the in-memory Merkle is rebuilt by appending the commit operation to the pinned
//! nodes, and a structurally invalid entry fails with [`Error::DataCorrupted`].
//!
//! Entries are strictly increasing in committed size, so a size uniquely identifies
//! a rewind or prune target. An appended entry becomes durable when the journal `commit` or
//! `sync` completes. For [`Store::start_sync`] it becomes durable when the returned handle
//! completes. Before that point, the entry is not guaranteed durable and recovery may fall back
//! to the previous commit. [`Store::prune`] bounds how far back [`Store::rewind`] can reach.
//! The tip entry is never pruned.

use super::variant::Variant;
use crate::{
    Context, SyncCompletion,
    journal::contiguous::{Contiguous, variable},
    merkle::{self, Family, Location, MAX_PINNED_NODES, Proof, batch, compact},
    qmdb::{
        self, Error,
        sync::{CompactTarget, Request, Response},
    },
};
use commonware_codec::{EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_runtime::{Error as RError, Handle};
use core::cmp::Ordering;
use futures::FutureExt as _;

/// An applied state persisted by the witness journal.
#[derive(Clone)]
pub(crate) struct Witness<F: Family, D: Digest, O> {
    /// The last commit operation, at `size - 1`.
    pub(crate) commit: O,
    /// The committed database size.
    pub(crate) size: Location<F>,
    /// Pinned nodes at the commit operation, in the order returned by
    /// [`Family::nodes_to_pin`].
    pub(crate) pinned_nodes: Vec<D>,
}

impl<F: Family, D: Digest, O: Variant<F>> EncodeSize for Witness<F, D, O> {
    fn encode_size(&self) -> usize {
        self.commit.encode_size() + self.size.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl<F: Family, D: Digest, O: Variant<F>> Write for Witness<F, D, O> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commit.write(buf);
        self.size.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl<F: Family, D: Digest, O: Variant<F>> Read for Witness<F, D, O> {
    type Cfg = O::Cfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &O::Cfg) -> Result<Self, commonware_codec::Error> {
        let commit = O::read_cfg(buf, cfg)?;
        let size = Location::<F>::read_cfg(buf, &())?;
        let pinned_nodes = Vec::<D>::read_cfg(buf, &((..=MAX_PINNED_NODES).into(), ()))?;
        Ok(Self {
            commit,
            size,
            pinned_nodes,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest, O> arbitrary::Arbitrary<'_> for Witness<F, D, O>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    O: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            commit: u.arbitrary()?,
            size: Location::new(u.int_in_range(1..=*F::MAX_LEAVES)?),
            pinned_nodes: u.arbitrary()?,
        })
    }
}

/// A witness whose commit has been checked and whose root and commit proof are derived from it.
#[derive(Clone)]
pub(crate) struct VerifiedWitness<F: Family, D: Digest, O: Variant<F>> {
    pub(crate) witness: Witness<F, D, O>,
    /// Inactivity floor declared by the commit. The root is computed over the peaks it leaves
    /// active.
    pub(crate) inactivity_floor_loc: Location<F>,
    /// Root committed by `witness`.
    pub(crate) root: D,
    /// Inclusion proof for the commit at `size - 1` against `root`, derived from the
    /// witness when it was built or loaded.
    pub(crate) proof: Proof<F, D>,
}

impl<F: Family, D: Digest, O: Variant<F>> VerifiedWitness<F, D, O> {
    /// The committed size, which also identifies the last commit's location.
    pub(crate) const fn size(&self) -> Location<F> {
        self.witness.size
    }

    /// The metadata carried by the commit.
    pub(crate) fn metadata(&self) -> Option<&O::Metadata> {
        self.witness.commit.metadata()
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
pub(crate) type Journal<E, F, D, O> = variable::Journal<E, Witness<F, D, O>>;

/// How a persisted witness entry is made durable.
#[derive(Clone, Copy)]
enum Durability {
    /// Commit the journal: appended entries survive a crash, but journal recovery may be
    /// required on reopen.
    Commit,
    /// Sync the journal and all of its metadata, minimizing recovery work on reopen.
    Sync,
}

/// The tip witness's relationship to the journal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TipState {
    /// Journaled and covered by a durability operation that has at least started.
    Committed,
    /// Journaled after the latest durability operation started.
    Uncommitted,
    /// From compact sync and not in the journal, which still holds the partition's previous
    /// contents until the first application or durability operation journals the tip in their
    /// place.
    Imported,
}

/// The compact Merkle, the contiguous journal of its witnesses, and an in-memory cache of the
/// tip witness.
pub(crate) struct Store<F: Family, E: Context, O: Variant<F>, H: Hasher, S: Strategy> {
    /// The peak-only Merkle the witnesses describe.
    merkle: compact::Merkle<F, H::Digest, S>,

    /// The journal of witnesses, one per applied batch.
    journal: Journal<E, F, H::Digest, O>,

    /// The verified witness at the journal tip.
    tip_witness: VerifiedWitness<F, H::Digest, O>,

    /// The tip witness's relationship to the journal.
    tip_state: TipState,

    /// The sync pipelined by the last [`Self::start_sync`], cleared by the next full
    /// journal sync.
    pending_sync: Option<SyncCompletion>,
}

impl<F: Family, E: Context, O: Variant<F>, H: Hasher, S: Strategy> Store<F, E, O, H, S> {
    /// Open the store for an existing or new compact db.
    ///
    /// A new db starts with one committed operation, the initial `Commit(None, 0)`: it is
    /// inserted into the compact Merkle and persisted as the first witness entry, so reopen and
    /// rewind never see an empty journal. An existing db reloads and re-verifies its tip witness.
    pub(crate) async fn init(
        mut journal: Journal<E, F, H::Digest, O>,
        strategy: S,
    ) -> Result<Self, Error<F>> {
        if journal.size() == 0 {
            // Leaf 0 has nothing pinned below it, so the genesis witness needs no tree.
            let genesis = Witness {
                commit: O::commit_op(None, Location::new(0)),
                size: Location::new(1),
                pinned_nodes: Vec::new(),
            };
            (journal, _) = journal.append(&genesis).await?;
            journal = journal.sync().await?;
        }
        let entry = journal.read(journal.size() - 1).await?;
        let Rebuilt { merkle, tip } = rebuild::<F, O, H, S>(strategy, entry)?;
        Ok(Self {
            merkle,
            journal,
            tip_witness: tip,
            tip_state: TipState::Committed,
            pending_sync: None,
        })
    }

    /// Create a store from a compact-sync import: `last_commit_op` must be a commit whose floor
    /// is at or below `last_commit_loc`. The journal is left untouched until the first
    /// application or durability operation replaces its contents with the imported witness; a
    /// crash during that replacement leaves a journal that fails to reopen, and re-syncing
    /// recovers it.
    pub(crate) fn from_import(
        journal: Journal<E, F, H::Digest, O>,
        strategy: S,
        last_commit_loc: Location<F>,
        pinned_nodes: Vec<H::Digest>,
        last_commit_op: O,
    ) -> Result<Self, Error<F>> {
        let Some(inactivity_floor_loc) = last_commit_op.has_floor() else {
            return Err(Error::UnexpectedData(last_commit_loc));
        };
        validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
        let witness = Witness {
            commit: last_commit_op,
            size: last_commit_loc + 1,
            pinned_nodes,
        };
        let Rebuilt { merkle, tip } =
            restore::<F, O, H, S>(strategy, witness, inactivity_floor_loc)?;
        Ok(Self {
            merkle,
            journal,
            tip_witness: tip,
            tip_state: TipState::Imported,
            pending_sync: None,
        })
    }

    /// The cached tip witness.
    pub(crate) const fn tip(&self) -> &VerifiedWitness<F, H::Digest, O> {
        &self.tip_witness
    }

    /// The compact Merkle.
    pub(crate) const fn merkle(&self) -> &compact::Merkle<F, H::Digest, S> {
        &self.merkle
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
    pub(crate) fn compact_state(
        &self,
        request: Request<F>,
    ) -> Result<Response<F, O, H::Digest>, Error<F>> {
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
        let op = self.tip_witness.witness.commit.clone();
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

    /// Apply `merkle_batch` to the Merkle and journal the witness for the new state, whose last
    /// operation is `commit` declaring `inactivity_floor_loc`. A pending compact-sync import is
    /// journaled first; a batch that adds no leaves leaves the tip unchanged.
    pub(crate) async fn apply(
        mut self,
        merkle_batch: &batch::MerkleizedBatch<F, H::Digest, S>,
        commit: O,
        inactivity_floor_loc: Location<F>,
    ) -> Result<Self, Error<F>> {
        debug_assert_eq!(self.tip_witness.size(), self.merkle.leaves());
        self.merkle.apply_batch(merkle_batch)?;
        let verified = match self.tip_witness.size().cmp(&self.merkle.leaves()) {
            Ordering::Equal => None,
            Ordering::Greater => {
                return Err(Error::DataCorrupted("witness ahead of in-memory state"));
            }
            // Build before pruning because the commit proof needs the unpruned Merkle.
            Ordering::Less => Some(build_witness::<F, H, S, O>(
                &self.merkle,
                commit,
                inactivity_floor_loc,
            )?),
        };
        // Journal the import before the new witness so every applied state has its own entry.
        self = self.flush_import().await?;
        if let Some(verified) = verified {
            self.tip_witness = verified;
            self.merkle.prune_to_frontier();
            self = self.journal_tip().await?;
        }
        Ok(self)
    }

    /// Journal a pending compact-sync import, if any, in place of the partition's previous
    /// contents.
    ///
    /// Clears to a nonzero size: if a crash interrupts the import, reopen sees an empty journal
    /// at a nonzero size, whose tip position is below its pruning boundary, and fails instead of
    /// mistaking it for a fresh db.
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
        (self.journal, _) = self.journal.append(&self.tip_witness.witness).await?;
        self.tip_state = TipState::Uncommitted;
        Ok(self)
    }

    /// Make the applied state durable by committing the journal, so every journaled witness
    /// survives a crash. Journal recovery may be required on reopen.
    ///
    /// First waits for any sync pipelined by [`Self::start_sync`], surfacing its failure, then
    /// journals a pending compact-sync import and commits.
    pub(crate) async fn commit(self) -> Result<Self, Error<F>> {
        self.wait_for_sync().await?;
        self.persist(Durability::Commit).await
    }

    /// Make the applied state durable by syncing the journal and all of its metadata, minimizing
    /// recovery work on reopen.
    ///
    /// Journals a pending compact-sync import first. This also settles any sync pipelined by
    /// [`Self::start_sync`].
    pub(crate) async fn sync(self) -> Result<Self, Error<F>> {
        self.persist(Durability::Sync).await
    }

    /// Shared body of [`Self::commit`] and [`Self::sync`]: journal a pending import, then make
    /// every uncommitted witness durable according to `durability`.
    async fn persist(mut self, durability: Durability) -> Result<Self, Error<F>> {
        self = self.flush_import().await?;

        // A commit leaves `pending_sync` set so the next full sync still persists all metadata.
        match durability {
            Durability::Commit if self.tip_state == TipState::Uncommitted => {
                self.journal = self.journal.commit().await?;
                self.tip_state = TipState::Committed;
            }
            Durability::Sync
                if self.tip_state == TipState::Uncommitted || self.pending_sync.is_some() =>
            {
                let journal = self.journal.sync().await?;
                self.pending_sync = None;
                self.tip_state = TipState::Committed;
                self.journal = journal;
            }
            Durability::Commit | Durability::Sync => {}
        }
        Ok(self)
    }

    /// Make the applied state durable by starting the journal sync instead of awaiting it.
    ///
    /// Journals a pending compact-sync import first. Awaiting the returned [Handle] provides the
    /// same durability guarantee as [Self::commit], plus a best-effort attempt to bound the
    /// recovery needed on reopen. When nothing new must be appended, the handle still proves the
    /// current tip durable and resurfaces any retained sync failure.
    pub(crate) async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error<F>> {
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

        // Share one completion between the caller and the store. Retaining a clone keeps a
        // dropped handle's failure observable by the next durability operation.
        let handle;
        (self.journal, handle) = self.journal.start_sync().await?;
        let completion: SyncCompletion = handle.boxed().shared();
        self.tip_state = TipState::Committed;
        self.pending_sync = Some(completion.clone());
        Ok((self, Handle::from_future(completion)))
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

    /// Rewind the journal so the entry committing exactly `target` leaves becomes the tip, then
    /// rebuild and re-verify the Merkle and cache from it. A committed tip already at `target`
    /// only settles its pipelined sync; an uncommitted tip at `target` takes the regular path
    /// so the journal becomes durable before return.
    ///
    /// Rewinding to a pruned size, or one no entry commits, returns
    /// [`merkle::Error::RewindBeyondHistory`]. The target entry is derived before the journal
    /// is truncated, so a corrupt entry fails the rewind with the journal intact. The rewind is
    /// made durable before returning.
    pub(crate) async fn rewind(mut self, target: Location<F>) -> Result<Self, Error<F>> {
        if self.tip_witness.size() == target && !self.has_uncommitted_state() {
            self.wait_for_sync().await?;
            return Ok(self);
        }
        self.check_import_applied()?;

        let (pos, entry) = self
            .position_of(target)
            .await?
            .ok_or(Error::Merkle(merkle::Error::RewindBeyondHistory))?;
        let Rebuilt { merkle, tip } = rebuild::<F, O, H, S>(self.merkle.strategy().clone(), entry)?;
        self.journal = self.journal.rewind(pos + 1).await?.sync().await?;
        self.merkle = merkle;
        self.pending_sync = None;
        self.tip_state = TipState::Committed;
        self.tip_witness = tip;
        Ok(self)
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
        self.tip_state = TipState::Committed;
        Ok(self)
    }

    /// Whether the current cached state is not covered by a durability operation.
    const fn has_uncommitted_state(&self) -> bool {
        !matches!(self.tip_state, TipState::Committed)
    }

    /// Reject operations on a journal whose contents an unapplied compact-sync import is
    /// about to replace.
    const fn check_import_applied(&self) -> Result<(), Error<F>> {
        if matches!(self.tip_state, TipState::Imported) {
            return Err(Error::DataCorrupted("compact-sync import not applied"));
        }
        Ok(())
    }

    /// Find the journal position and entry committing exactly `target` leaves, or `None` if
    /// no retained entry does.
    async fn position_of(
        &self,
        target: Location<F>,
    ) -> Result<Option<(u64, Witness<F, H::Digest, O>)>, Error<F>> {
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
        reader: &impl Contiguous<Item = Witness<F, H::Digest, O>>,
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

    /// Destroy all persisted witness state.
    pub(crate) async fn destroy(self) -> Result<(), Error<F>> {
        self.journal.destroy().await?;
        Ok(())
    }
}

/// Build a witness for `commit`, the last operation in `merkle`.
///
/// The tip operation's inclusion proof is only computable before the Merkle is pruned to its
/// frontier.
fn build_witness<F, H, S, O>(
    merkle: &compact::Merkle<F, H::Digest, S>,
    commit: O,
    inactivity_floor_loc: Location<F>,
) -> Result<VerifiedWitness<F, H::Digest, O>, Error<F>>
where
    F: Family,
    H: Hasher,
    S: Strategy,
    O: Variant<F>,
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
            commit,
            size,
            pinned_nodes,
        },
        inactivity_floor_loc,
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

/// A Merkle materialized from a witness, with the witness verified against it.
struct Rebuilt<F: Family, D: Digest, O: Variant<F>, S: Strategy> {
    merkle: compact::Merkle<F, D, S>,
    tip: VerifiedWitness<F, D, O>,
}

/// Materialize the tree `witness` describes and derive its root and commit proof.
///
/// The tree is built from the pinned nodes one operation below the commit plus the commit
/// itself, then pruned back to its frontier. Merkle errors propagate unchanged.
fn restore<F, O, H, S>(
    strategy: S,
    witness: Witness<F, H::Digest, O>,
    inactivity_floor_loc: Location<F>,
) -> Result<Rebuilt<F, H::Digest, O, S>, Error<F>>
where
    F: Family,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    let Witness {
        commit,
        size,
        pinned_nodes,
    } = witness;
    let Some(last_commit_loc) = size.checked_sub(1) else {
        return Err(Error::DataCorrupted("invalid compact witness"));
    };
    let mut merkle = compact::Merkle::from_compact_state(strategy, last_commit_loc, pinned_nodes)?;
    merkle.append_leaf(&qmdb::hasher::<H>(), &commit.encode())?;
    let tip = build_witness::<F, H, S, O>(&merkle, commit, inactivity_floor_loc)?;
    merkle.prune_to_frontier();
    Ok(Rebuilt { merkle, tip })
}

/// Validate a journaled witness, then restore it. Any failure is [`Error::DataCorrupted`]: the
/// entry came from this db's own journal.
fn rebuild<F, O, H, S>(
    strategy: S,
    witness: Witness<F, H::Digest, O>,
) -> Result<Rebuilt<F, H::Digest, O, S>, Error<F>>
where
    F: Family,
    O: Variant<F>,
    H: Hasher,
    S: Strategy,
{
    let Some(last_commit_loc) = witness.size.checked_sub(1) else {
        return Err(Error::DataCorrupted("invalid compact witness"));
    };
    // The floor determines the inactive peak boundary used for root computation.
    let Some(inactivity_floor_loc) = witness.commit.has_floor() else {
        return Err(Error::DataCorrupted("last operation was not a commit"));
    };
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;

    restore::<F, O, H, S>(strategy, witness, inactivity_floor_loc)
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::{
            merkle::{mmb, mmr},
            qmdb::{
                any::value::{FixedEncoding, VariableEncoding},
                keyless::Operation,
            },
        };
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256;
        use commonware_utils::sequence::U64;

        commonware_conformance::conformance_tests! {
            CodecConformance<Witness<mmr::Family, sha256::Digest, Operation<mmr::Family, FixedEncoding<U64>>>>,
            CodecConformance<Witness<mmb::Family, sha256::Digest, Operation<mmb::Family, FixedEncoding<U64>>>>,
            CodecConformance<Witness<mmr::Family, sha256::Digest, Operation<mmr::Family, VariableEncoding<U64>>>>,
        }
    }

    /// Corrupt the entry at `pos` with `f`, preserving the entries above it.
    pub(crate) async fn corrupt_entry<E, F, D, O>(
        journal: Journal<E, F, D, O>,
        pos: u64,
        f: impl FnOnce(&mut Witness<F, D, O>),
    ) -> Journal<E, F, D, O>
    where
        E: Context,
        F: Family,
        D: Digest,
        O: Variant<F>,
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
    pub(crate) async fn tip<E, F, D, O>(journal: &Journal<E, F, D, O>) -> (O, Location<F>, Vec<D>)
    where
        E: Context,
        F: Family,
        D: Digest,
        O: Variant<F>,
    {
        let size = journal.size();
        let entry = journal.read(size - 1).await.unwrap();
        (entry.commit, entry.size, entry.pinned_nodes)
    }

    /// Append a witness entry without syncing it.
    pub(crate) async fn append_unsynced<E, F, D, O>(
        journal: Journal<E, F, D, O>,
        commit: O,
        size: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Journal<E, F, D, O>
    where
        E: Context,
        F: Family,
        D: Digest,
        O: Variant<F>,
    {
        let (journal, _) = journal
            .append(&Witness {
                commit,
                size,
                pinned_nodes,
            })
            .await
            .unwrap();
        journal
    }

    /// Replace the tip witness entry.
    pub(crate) async fn overwrite_tip<E, F, D, O>(
        journal: Journal<E, F, D, O>,
        commit: O,
        size: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Journal<E, F, D, O>
    where
        E: Context,
        F: Family,
        D: Digest,
        O: Variant<F>,
    {
        let entries = journal.size();
        let journal = journal.rewind(entries - 1).await.unwrap();
        let (journal, _) = journal
            .append(&Witness {
                commit,
                size,
                pinned_nodes,
            })
            .await
            .unwrap();
        journal.sync().await.unwrap()
    }
}
