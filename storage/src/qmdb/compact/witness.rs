//! Shared machinery for the compact-db witness journal.
//!
//! The witness journal is the single durable source of truth for a compact database. Each
//! [`Witness`] is a complete snapshot of one synced commit: the encoded commit operation,
//! its single-leaf inclusion proof against the committed root, and the pinned frontier nodes of
//! the compact Merkle. On open and rewind, the in-memory Merkle is rebuilt from an entry and the
//! entry's proof is re-verified against the root recomputed from the rebuilt frontier; a
//! mismatch fails with [`Error::DataCorrupted`].
//!
//! Entries are strictly increasing in committed leaf count (`proof.leaves`), so a leaf count
//! uniquely identifies a rewind or prune target. The journal `commit` or `sync` after an append
//! is the commit point: a crash before it drops the unsynced tail on reopen, recovering the
//! previous commit. [`Store::prune`] bounds how far back [`Store::rewind`] can reach; the tip
//! entry is never pruned.

use crate::{
    journal::contiguous::{variable, Reader as _},
    merkle::{
        self, compact, Family, Location, Proof, MAX_PINNED_NODES, MAX_PROOF_DIGESTS_PER_ELEMENT,
    },
    qmdb::{self, sync::compact::Target, Error},
    Context,
};
use commonware_codec::{Decode as _, EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::sync::{AsyncMutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};

/// A single durably persisted witness: a complete snapshot of one synced commit.
///
/// The root is not stored: it is recomputed from the rebuilt frontier and authenticated against
/// `proof`.
#[derive(Clone)]
pub(crate) struct Witness<F: Family, D: Digest> {
    /// The encoded last-commit operation.
    pub(crate) op_bytes: Vec<u8>,
    /// Inclusion proof for the last-commit leaf; its `leaves` field identifies the committed
    /// leaf count.
    pub(crate) proof: Proof<F, D>,
    /// Pinned frontier nodes of the committed Merkle; with `proof.leaves`, everything needed
    /// to rebuild the in-memory Merkle for this commit.
    pub(crate) pinned_nodes: Vec<D>,
}

impl<F: Family, D: Digest> EncodeSize for Witness<F, D> {
    fn encode_size(&self) -> usize {
        self.op_bytes.encode_size() + self.proof.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl<F: Family, D: Digest> Write for Witness<F, D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.op_bytes.write(buf);
        self.proof.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl<F: Family, D: Digest> Read for Witness<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let op_bytes = Vec::<u8>::read_cfg(buf, &((..).into(), ()))?;
        let proof = Proof::<F, D>::read_cfg(buf, &MAX_PROOF_DIGESTS_PER_ELEMENT)?;
        let pinned_nodes = Vec::<D>::read_cfg(buf, &((..=MAX_PINNED_NODES).into(), ()))?;
        Ok(Self {
            op_bytes,
            proof,
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
            proof: u.arbitrary()?,
            pinned_nodes: u.arbitrary()?,
        })
    }
}

/// A witness and the root it was verified against.
#[derive(Clone)]
pub(crate) struct VerifiedWitness<F: Family, D: Digest> {
    pub(crate) witness: Witness<F, D>,
    /// Root committed by `witness`.
    pub(crate) root: D,
}

impl<F: Family, D: Digest> VerifiedWitness<F, D> {
    /// Total leaves in the committed Merkle, which also identifies the last commit's location.
    pub(crate) const fn leaf_count(&self) -> Location<F> {
        self.witness.proof.leaves
    }

    /// The compact-sync target this witness can serve: its root and leaf count.
    pub(crate) const fn target(&self) -> Target<F, D> {
        Target {
            root: self.root,
            leaf_count: self.leaf_count(),
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

    tip_witness: RwLock<VerifiedWitness<F, D>>,

    /// Whether the cached witness came from compact sync and has not been written to the
    /// journal yet. While set, the journal still holds the partition's previous contents; the
    /// first persist replaces them with the cached witness and clears this flag. Mutated only
    /// under `sync_lock`; reads hold `sync_lock` or the db's `&mut`, so `Relaxed` suffices.
    import_pending: AtomicBool,

    /// Serializes persist/rewind/prune.
    sync_lock: AsyncMutex<()>,
}

impl<E: Context, F: Family, D: Digest> Store<E, F, D> {
    /// Wrap an opened journal and a verified witness into a store.
    pub(crate) fn new(journal: Journal<E, F, D>, witness: VerifiedWitness<F, D>) -> Self {
        Self {
            journal,
            tip_witness: RwLock::new(witness),
            import_pending: AtomicBool::new(false),
            sync_lock: AsyncMutex::new(()),
        }
    }

    /// Create a store from a validated compact-sync import that has not been persisted yet. The
    /// journal is untouched until the first persist replaces its contents with `witness`. A
    /// crash during that replacement leaves a journal that fails to reopen; re-syncing
    /// recovers it.
    pub(crate) fn from_import(journal: Journal<E, F, D>, witness: VerifiedWitness<F, D>) -> Self {
        Self {
            journal,
            tip_witness: RwLock::new(witness),
            import_pending: AtomicBool::new(true),
            sync_lock: AsyncMutex::new(()),
        }
    }

    /// Read the cached witness without exposing the underlying lock to db code.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&VerifiedWitness<F, D>) -> R) -> R {
        f(&self.tip_witness.read())
    }

    /// Replace the cached witness after the matching compact Merkle state is persisted or loaded.
    pub(crate) fn replace(&self, witness: VerifiedWitness<F, D>) {
        *self.tip_witness.write() = witness;
    }

    /// Persist the current compact state as a new witness journal entry, committing the journal
    /// so the entry survives a crash. Journal recovery may be required on reopen.
    ///
    /// No-op if the cached witness already matches the Merkle (the witness is already durable).
    /// Otherwise appends a witness built from the unpruned Merkle, prunes the Merkle to its
    /// frontier, and refreshes the cache.
    pub(crate) async fn commit<H, S>(
        &self,
        merkle: &compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
    ) -> Result<(), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
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
    /// No-op if the cached witness already matches the Merkle (the witness is already durable).
    /// Otherwise appends a witness built from the unpruned Merkle, prunes the Merkle to its
    /// frontier, and refreshes the cache.
    pub(crate) async fn sync<H, S>(
        &self,
        merkle: &compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
    ) -> Result<(), Error<F>>
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

    /// Shared body of [`Self::commit`] and [`Self::sync`]: stage what must be persisted, append
    /// it, make it durable per `durability`, and install it as the cached tip.
    ///
    /// A pending import is cleared only after the entry is durable, so an interrupted journal
    /// replacement is retried by the next persist.
    async fn persist<H, S>(
        &self,
        merkle: &compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
        durability: Durability,
    ) -> Result<(), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let _guard = self.sync_lock.lock().await;
        let Some(verified) = self
            .stage::<H, S>(merkle, inactivity_floor_loc, last_commit_op_bytes)
            .await?
        else {
            return Ok(());
        };
        self.journal.append(&verified.witness).await?;
        match durability {
            Durability::Commit => self.journal.commit().await?,
            Durability::Sync => self.journal.sync().await?,
        }
        self.import_pending.store(false, Ordering::Relaxed);
        merkle.prune_to_frontier();
        self.replace(verified);
        Ok(())
    }

    /// Decide what a persist must write, clearing the journal first when an import is pending.
    /// Callers must hold `sync_lock`.
    ///
    /// Returns `None` if the durable tip already matches the in-memory Merkle and no import is
    /// pending, otherwise the witness to append and install in the cache.
    async fn stage<H, S>(
        &self,
        merkle: &compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
    ) -> Result<Option<VerifiedWitness<F, D>>, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        // An equal leaf count means no commit has been applied since the cache was set.
        // Normally the cache mirrors the journal tip, so the state is already durable and there
        // is nothing to do. During a pending import the cached witness is not in the journal
        // yet, so it is exactly what must be persisted: replace the journal's contents with it.
        let cached_leaves = self.with(|w| w.leaf_count());
        let verified = if cached_leaves == merkle.leaves() {
            if !self.import_pending.load(Ordering::Relaxed) {
                return Ok(None);
            }
            self.with(|w| w.clone())
        } else if cached_leaves > merkle.leaves() {
            return Err(Error::DataCorrupted("witness ahead of in-memory state"));
        } else {
            build_witness::<F, H, S>(merkle, inactivity_floor_loc, last_commit_op_bytes())?
        };
        if self.import_pending.load(Ordering::Relaxed) {
            self.clear_for_import().await?;
        }
        Ok(Some(verified))
    }

    /// Rewind the journal so the entry committing exactly `target` leaves becomes the tip, then
    /// rebuild and re-verify the Merkle and cache from it. Returns the decoded commit operation
    /// of the restored tip.
    ///
    /// Rewinding to a pruned leaf count, or one no entry commits, returns
    /// [`merkle::Error::RewindBeyondHistory`]. The target entry is verified before the journal
    /// is truncated, so a corrupt entry fails the rewind with the journal intact. The rewind is
    /// made durable before returning.
    pub(crate) async fn rewind<H, S, Op>(
        &self,
        merkle: &compact::Merkle<F, D, S>,
        target: Location<F>,
        commit_codec_config: &Op::Cfg,
        last_commit_floor: impl FnOnce(&Op) -> Option<Location<F>>,
    ) -> Result<Op, Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Read,
    {
        let _guard = self.sync_lock.lock().await;
        self.check_import_persisted()?;

        let (pos, entry) = self
            .position_of(target)
            .await?
            .ok_or(Error::Merkle(merkle::Error::RewindBeyondHistory))?;
        let (witness, op) = rebuild_and_verify::<F, D, H, S, Op>(
            entry,
            merkle,
            commit_codec_config,
            last_commit_floor,
        )?;
        self.journal.rewind(pos + 1).await?;
        self.journal.sync().await?;
        self.replace(witness);
        Ok(op)
    }

    /// Drop all entries committing fewer than `pruning_boundary` leaves, bounding how far back
    /// [`Self::rewind`] can reach. The tip entry always survives. Some entries
    /// below the boundary may survive.
    pub(crate) async fn prune(&self, pruning_boundary: Location<F>) -> Result<(), Error<F>> {
        let _guard = self.sync_lock.lock().await;
        self.check_import_persisted()?;

        let reader = self.journal.reader().await;
        let bounds = reader.bounds();
        if bounds.is_empty() {
            return Ok(());
        }
        // Clamp below the tip so the journal never empties: the tip is the current state.
        let pos = Self::first_at_or_above(&reader, pruning_boundary)
            .await?
            .min(bounds.end - 1);
        // Release the read guard before mutating the journal.
        drop(reader);
        self.journal.prune(pos).await?;
        self.journal.sync().await?;
        Ok(())
    }

    /// Whether a compact-sync import is not yet durable.
    pub(crate) fn import_pending(&self) -> bool {
        self.import_pending.load(Ordering::Relaxed)
    }

    /// Reject operations on a journal whose contents an unpersisted compact-sync import is
    /// about to replace.
    fn check_import_persisted(&self) -> Result<(), Error<F>> {
        if self.import_pending.load(Ordering::Relaxed) {
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
        let reader = self.journal.reader().await;
        let pos = Self::first_at_or_above(&reader, target).await?;
        if pos >= reader.bounds().end {
            return Ok(None);
        }
        let entry = reader.read(pos).await?;
        Ok((entry.proof.leaves == target).then_some((pos, entry)))
    }

    /// Binary search for the first retained position whose entry commits at least `leaf_count`
    /// leaves, or the end of the journal if none does.
    async fn first_at_or_above(
        reader: &variable::Reader<'_, E, Witness<F, D>>,
        leaf_count: Location<F>,
    ) -> Result<u64, Error<F>> {
        let bounds = reader.bounds();
        let (mut lo, mut hi) = (bounds.start, bounds.end);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if reader.read(mid).await?.proof.leaves < leaf_count {
                // The entry at `mid` is below `leaf_count`, so the answer is after it.
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
    async fn clear_for_import(&self) -> Result<(), Error<F>> {
        let size = self.journal.size().await;
        self.journal.clear_to_size(size.max(1)).await?;
        Ok(())
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
fn build_witness<F, H, S>(
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
    merkle.with_mem(|mem| {
        let leaf_count = mem.leaves();
        let last_commit_loc = Location::new(*leaf_count - 1);
        let inactive_peaks =
            F::inactive_peaks(F::location_to_position(leaf_count), inactivity_floor_loc);
        let root = mem.root(&hasher, inactive_peaks)?;
        let pinned_nodes = F::nodes_to_pin(leaf_count)
            .map(|pos| *mem.get_node_unchecked(pos))
            .collect::<Vec<_>>();
        let proof = mem.proof(&hasher, last_commit_loc, inactive_peaks)?;
        Ok(VerifiedWitness {
            witness: Witness {
                op_bytes: last_commit_op_bytes,
                proof,
                pinned_nodes,
            },
            root,
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
    last_commit_floor: impl FnOnce(&Op) -> Option<Location<F>>,
) -> Result<(VerifiedWitness<F, H::Digest>, Op), Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Read,
{
    let size = journal.size().await;
    if size == 0 {
        return Err(Error::DataCorrupted("missing compact witness"));
    }
    let entry = {
        let reader = journal.reader().await;
        reader.read(size - 1).await?
    };
    rebuild_and_verify::<F, H::Digest, H, S, Op>(
        entry,
        merkle,
        commit_codec_config,
        last_commit_floor,
    )
}

/// Rebuild the Merkle from `witness` and verify the witness against it.
///
/// The Merkle is reset to the witness's `(leaf_count, pinned_nodes)`, the root is recomputed
/// from the rebuilt frontier, and the witness's proof is verified against that root.
fn rebuild_and_verify<F, D, H, S, Op>(
    witness: Witness<F, D>,
    merkle: &compact::Merkle<F, D, S>,
    commit_codec_config: &Op::Cfg,
    last_commit_floor: impl FnOnce(&Op) -> Option<Location<F>>,
) -> Result<(VerifiedWitness<F, D>, Op), Error<F>>
where
    F: Family,
    D: Digest,
    H: Hasher<Digest = D>,
    S: Strategy,
    Op: Read,
{
    let leaf_count = witness.proof.leaves;
    if leaf_count == 0 {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }

    // Decode the commit op to get the inactivity floor, which determines the inactive peak
    // boundary used for root computation.
    let last_commit_loc = Location::new(*leaf_count - 1);
    let last_commit_op = Op::decode_cfg(witness.op_bytes.as_ref(), commit_codec_config)
        .map_err(|_| Error::DataCorrupted("invalid commit operation"))?;
    let inactivity_floor_loc = last_commit_floor(&last_commit_op)
        .ok_or(Error::DataCorrupted("last operation was not a commit"))?;
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;

    merkle
        .reset_to(leaf_count, witness.pinned_nodes.clone())
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    let inactive_peaks =
        F::inactive_peaks(F::location_to_position(leaf_count), inactivity_floor_loc);
    let hasher = qmdb::hasher::<H>();
    let root = merkle
        .root(&hasher, inactive_peaks)
        .map_err(|_| Error::DataCorrupted("failed to compute compact witness root"))?;
    if !witness.proof.verify_range_inclusion(
        &hasher,
        &[witness.op_bytes.as_slice()],
        last_commit_loc,
        &root,
    ) {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }
    Ok((VerifiedWitness { witness, root }, last_commit_op))
}

/// Open the witness store for an existing or new compact db, returning it with the decoded
/// last-commit operation.
///
/// A new db starts with one committed operation, the initial commit: it is inserted into the
/// compact Merkle and persisted as the first witness entry, so reopen and rewind never see an
/// empty journal. An existing db reloads and re-verifies its tip witness.
pub(crate) async fn init<E, F, H, S, Op>(
    journal: Journal<E, F, H::Digest>,
    merkle: &mut compact::Merkle<F, H::Digest, S>,
    commit_codec_config: &Op::Cfg,
    initial_commit_op_bytes: Vec<u8>,
    last_commit_floor: impl FnOnce(&Op) -> Option<Location<F>>,
) -> Result<(Store<E, F, H::Digest>, Op), Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Read,
{
    if journal.size().await == 0 {
        bootstrap_initial_commit::<E, F, H, S>(&journal, merkle, initial_commit_op_bytes).await?;
    }
    let (witness, op) =
        load_tip::<E, F, H, S, Op>(&journal, merkle, commit_codec_config, last_commit_floor)
            .await?;
    Ok((Store::new(journal, witness), op))
}

/// Insert and persist the initial `Commit(None, 0)` for a new compact db.
async fn bootstrap_initial_commit<E, F, H, S>(
    journal: &Journal<E, F, H::Digest>,
    merkle: &mut compact::Merkle<F, H::Digest, S>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<(), Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
{
    let hasher = qmdb::hasher::<H>();
    let batch = {
        let batch = merkle.new_batch().add(&hasher, &last_commit_op_bytes);
        merkle.with_mem(|mem| batch.merkleize(mem, &hasher))
    };
    merkle.apply_batch(&batch)?;

    // The initial commit has one leaf and an inactivity floor of 0.
    let verified = build_witness::<F, H, S>(merkle, Location::new(0), last_commit_op_bytes)?;
    journal.append(&verified.witness).await?;
    journal.sync().await?;
    Ok(())
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
        journal: &Journal<E, F, D>,
        pos: u64,
        f: impl FnOnce(&mut Witness<F, D>),
    ) where
        E: Context,
        F: Family,
        D: Digest,
    {
        let mut entries = Vec::new();
        {
            let reader = journal.reader().await;
            for p in pos..reader.bounds().end {
                entries.push(reader.read(p).await.unwrap());
            }
        }
        f(&mut entries[0]);
        journal.rewind(pos).await.unwrap();
        for entry in &entries {
            journal.append(entry).await.unwrap();
        }
        journal.sync().await.unwrap();
    }

    /// Read the tip witness entry's components.
    pub(crate) async fn tip<E, F, D>(journal: &Journal<E, F, D>) -> (Vec<u8>, Proof<F, D>, Vec<D>)
    where
        E: Context,
        F: Family,
        D: Digest,
    {
        let size = journal.size().await;
        let entry = {
            let reader = journal.reader().await;
            reader.read(size - 1).await.unwrap()
        };
        (entry.op_bytes, entry.proof, entry.pinned_nodes)
    }

    /// Append a witness entry without syncing it.
    pub(crate) async fn append_unsynced<E, F, D>(
        journal: &Journal<E, F, D>,
        op_bytes: Vec<u8>,
        proof: Proof<F, D>,
        pinned_nodes: Vec<D>,
    ) where
        E: Context,
        F: Family,
        D: Digest,
    {
        journal
            .append(&Witness {
                op_bytes,
                proof,
                pinned_nodes,
            })
            .await
            .unwrap();
    }

    /// Replace the tip witness entry.
    pub(crate) async fn overwrite_tip<E, F, D>(
        journal: &Journal<E, F, D>,
        op_bytes: Vec<u8>,
        proof: Proof<F, D>,
        pinned_nodes: Vec<D>,
    ) where
        E: Context,
        F: Family,
        D: Digest,
    {
        let size = journal.size().await;
        journal.rewind(size - 1).await.unwrap();
        journal
            .append(&Witness {
                op_bytes,
                proof,
                pinned_nodes,
            })
            .await
            .unwrap();
        journal.sync().await.unwrap();
    }
}
