//! Shared machinery for the compact-db witness journal.
//!
//! The witness journal is the single durable source of truth for a compact database. Every
//! durable sync appends exactly one [`WitnessEntry`]: the encoded commit operation, its
//! single-leaf inclusion proof against the committed root, and the pinned frontier nodes of the
//! compact Merkle. An entry is therefore a complete snapshot of one synced commit: the in-memory
//! Merkle is rebuilt from the tip entry on reopen and from an older entry on rewind.
//!
//! This state lives at the db layer rather than the Merkle layer because only the db knows how to
//! encode and decode the typed commit operation. Both [`crate::qmdb::immutable::CompactDb`] and
//! [`crate::qmdb::keyless::CompactDb`] keep the witness in a db-owned [`Store`] backed by a
//! contiguous variable journal, then re-verify the tip proof against the recomputed root on every
//! reopen and rewind. If the tip entry no longer describes a valid witness for the rebuilt
//! frontier, reopening fails with [`Error::DataCorrupted`].
//!
//! # Journal layout and crash consistency
//!
//! Entries are strictly increasing in committed leaf count (`proof.leaves`); every append path
//! upholds this invariant. Since journal positions are also stable across pruning, rewind and
//! prune targets are located by binary search on leaf count.
//!
//! The journal `sync` after an append is the commit point: a crash before it drops the unsynced
//! tail on reopen, recovering the previous commit. The Merkle persists nothing, so there is
//! nothing else to reconcile. Rewind truncates the journal to the target entry and syncs. Only
//! the tip entry is ever verified: on reopen, or when a rewind makes an older entry the tip.
//!
//! [`Store::prune`] bounds how far back [`Store::rewind`] can reach; the tip entry is never
//! pruned.

use crate::{
    journal::contiguous::{variable, Reader as _},
    merkle::{
        self, compact, Family, Location, Proof, MAX_PINNED_NODES, MAX_PROOF_DIGESTS_PER_ELEMENT,
    },
    qmdb::{self, sync::compact::Target, Error},
    Context,
};
use commonware_codec::{Decode as _, EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::sync::{AsyncMutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};

/// Upper bound on the encoded last-commit operation, enforced at commit time and as a decode
/// guard against corrupted length prefixes. Commit operations are small; this bound is
/// intentionally generous because the commit carries optional caller metadata.
pub(crate) const MAX_OP_BYTES: usize = 1 << 24;

/// Codec configuration for decoding a [`WitnessEntry`] read back from the journal.
#[derive(Clone)]
pub(crate) struct WitnessEntryCfg {
    op_bytes: RangeCfg<usize>,
    proof_digests: usize,
    pinned_nodes: RangeCfg<usize>,
}

impl Default for WitnessEntryCfg {
    fn default() -> Self {
        Self {
            op_bytes: (..=MAX_OP_BYTES).into(),
            proof_digests: MAX_PROOF_DIGESTS_PER_ELEMENT,
            pinned_nodes: (..=MAX_PINNED_NODES).into(),
        }
    }
}

/// A single durably persisted witness: the encoded last-commit operation, its inclusion proof,
/// and the pinned frontier nodes of the committed Merkle.
///
/// The proof's `leaves` field identifies the committed leaf count; together with `pinned_nodes`
/// it is everything required to rebuild the in-memory Merkle for this commit. The root is not
/// stored: it is recomputed from the rebuilt frontier and authenticated against the proof.
#[derive(Clone)]
pub(crate) struct WitnessEntry<F: Family, D: Digest> {
    op_bytes: Vec<u8>,
    proof: Proof<F, D>,
    pinned_nodes: Vec<D>,
}

impl<F: Family, D: Digest> EncodeSize for WitnessEntry<F, D> {
    fn encode_size(&self) -> usize {
        self.op_bytes.encode_size() + self.proof.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl<F: Family, D: Digest> Write for WitnessEntry<F, D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.op_bytes.write(buf);
        self.proof.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl<F: Family, D: Digest> Read for WitnessEntry<F, D> {
    type Cfg = WitnessEntryCfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let op_bytes = Vec::<u8>::read_cfg(buf, &(cfg.op_bytes, ()))?;
        let proof = Proof::<F, D>::read_cfg(buf, &cfg.proof_digests)?;
        let pinned_nodes = Vec::<D>::read_cfg(buf, &(cfg.pinned_nodes, ()))?;
        Ok(Self {
            op_bytes,
            proof,
            pinned_nodes,
        })
    }
}

impl<F: Family, D: Digest> From<&Witness<F, D>> for WitnessEntry<F, D> {
    fn from(witness: &Witness<F, D>) -> Self {
        Self {
            op_bytes: witness.last_commit_op_bytes.clone(),
            proof: witness.last_commit_proof.clone(),
            pinned_nodes: witness.pinned_nodes.clone(),
        }
    }
}

/// The contiguous variable journal that backs a witness [`Store`].
pub(crate) type Journal<E, F, D> = variable::Journal<E, WitnessEntry<F, D>>;

/// In-memory snapshot of the tip witness.
#[derive(Clone)]
pub(crate) struct Witness<F: Family, D: Digest> {
    /// Root committed by the tip witness entry.
    pub(crate) root: D,
    /// Total leaves in the committed Merkle, which also identifies the tip commit location.
    pub(crate) leaf_count: Location<F>,
    /// Frontier nodes pinned by compact sync; these are the persisted peaks, not the proof path.
    pub(crate) pinned_nodes: Vec<D>,
    /// Encoded last-commit operation bytes used for root verification and serving.
    pub(crate) last_commit_op_bytes: Vec<u8>,
    /// Inclusion proof for the last-commit leaf against `root`.
    pub(crate) last_commit_proof: Proof<F, D>,
}

impl<F: Family, D: Digest> Witness<F, D> {
    /// The compact-sync target this witness can serve: its root and leaf count.
    pub(crate) const fn target(&self) -> Target<F, D> {
        Target {
            root: self.root,
            leaf_count: self.leaf_count,
        }
    }
}

/// Open the witness journal for a compact db.
pub(crate) async fn open_journal<E, F, D>(
    context: E,
    cfg: variable::Config<()>,
) -> Result<Journal<E, F, D>, Error<F>>
where
    E: Context,
    F: Family,
    D: Digest,
{
    let cfg = variable::Config {
        partition: cfg.partition,
        items_per_section: cfg.items_per_section,
        compression: cfg.compression,
        // Callers pass `()` because [`WitnessEntryCfg`] is internal to this module.
        codec_config: WitnessEntryCfg::default(),
        page_cache: cfg.page_cache,
        write_buffer: cfg.write_buffer,
    };
    Ok(variable::Journal::init(context, cfg).await?)
}

/// A contiguous journal plus an in-memory cache of the tip witness.
pub(crate) struct Store<E: Context, F: Family, D: Digest> {
    journal: Journal<E, F, D>,
    cache: RwLock<Witness<F, D>>,
    /// Whether the cached witness came from compact sync and has not been written to the
    /// journal yet. While set, the journal still holds the partition's previous contents; the
    /// first persist replaces them with the cached witness and clears this flag. Accessed only
    /// under `sync_lock`, so loads and stores are `Relaxed`.
    import_pending: AtomicBool,
    /// Serializes persist/rewind/prune so concurrent calls on a shared handle do not interleave.
    sync_lock: AsyncMutex<()>,
}

impl<E: Context, F: Family, D: Digest> Store<E, F, D> {
    /// Wrap an opened journal and a verified witness into a store.
    pub(crate) fn new(journal: Journal<E, F, D>, witness: Witness<F, D>) -> Self {
        Self {
            journal,
            cache: RwLock::new(witness),
            import_pending: AtomicBool::new(false),
            sync_lock: AsyncMutex::new(()),
        }
    }

    /// Wrap a journal and a verified compact-sync import that has not been persisted yet; the
    /// journal is untouched until the first persist replaces its contents with `witness`.
    pub(crate) fn from_import(journal: Journal<E, F, D>, witness: Witness<F, D>) -> Self {
        Self {
            journal,
            cache: RwLock::new(witness),
            import_pending: AtomicBool::new(true),
            sync_lock: AsyncMutex::new(()),
        }
    }

    /// Read the cached witness without exposing the underlying lock to db code.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&Witness<F, D>) -> R) -> R {
        f(&self.cache.read())
    }

    /// Replace the cached witness after the matching compact Merkle state is persisted or loaded.
    pub(crate) fn replace(&self, witness: Witness<F, D>) {
        *self.cache.write() = witness;
    }

    /// Persist the current compact state as a new witness journal entry.
    ///
    /// No-op if the cached witness already matches the Merkle (the witness is already durable).
    /// Otherwise appends a witness built from the unpruned Merkle, prunes the Merkle to its
    /// frontier, and refreshes the cache.
    pub(crate) async fn persist<H, S>(
        &self,
        merkle: &compact::Merkle<F, D, S>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: impl FnOnce() -> Vec<u8>,
    ) -> Result<(), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let _guard = self.sync_lock.lock().await;

        // An equal leaf count means no commit has been applied since the cache was set.
        // Normally the cache mirrors the journal tip, so the state is already durable and there
        // is nothing to do. During a pending import the cached witness is not in the journal
        // yet, so it is exactly what must be persisted: replace the journal's contents with it.
        let cached_leaves = self.with(|w| w.leaf_count);
        if cached_leaves == merkle.leaves() {
            if self.import_pending.load(Ordering::Relaxed) {
                self.journal.clear_to_size(0).await?;
                let entry = self.with(|w| WitnessEntry::from(w));
                self.append_and_sync(&entry).await?;
                // Cleared only after the replacement completes so an interrupted one is retried.
                self.import_pending.store(false, Ordering::Relaxed);
            }
            return Ok(());
        }
        if cached_leaves > merkle.leaves() {
            return Err(Error::DataCorrupted("witness ahead of in-memory state"));
        }

        let last_commit_op_bytes = last_commit_op_bytes();
        if last_commit_op_bytes.len() > MAX_OP_BYTES {
            return Err(Error::CommitTooLarge(
                last_commit_op_bytes.len(),
                MAX_OP_BYTES,
            ));
        }
        let witness = build_witness::<F, H, S>(merkle, inactivity_floor_loc, last_commit_op_bytes)?;
        if self.import_pending.load(Ordering::Relaxed) {
            self.journal.clear_to_size(0).await?;
        }
        self.append_and_sync(&WitnessEntry::from(&witness)).await?;
        self.import_pending.store(false, Ordering::Relaxed);
        merkle.prune_to_frontier();
        self.replace(witness);
        Ok(())
    }

    /// Rewind the journal so the entry committing exactly `target` leaves becomes the tip, then
    /// rebuild and re-verify the Merkle and cache from it. Returns the decoded commit operation
    /// of the restored tip.
    ///
    /// Rewinding to a pruned leaf count, or one no entry commits, returns
    /// [`merkle::Error::RewindBeyondHistory`]. The rewind is synced before returning.
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

        let pos = self
            .position_of(target)
            .await?
            .ok_or(Error::Merkle(merkle::Error::RewindBeyondHistory))?;
        self.journal.rewind(pos + 1).await?;
        self.journal.sync().await?;

        let (witness, op) = load_tip::<E, F, H, S, Op>(
            &self.journal,
            merkle,
            commit_codec_config,
            last_commit_floor,
        )
        .await?;
        self.replace(witness);
        Ok(op)
    }

    /// Drop all entries committing fewer than `pruning_boundary` leaves, bounding how far back
    /// [`Self::rewind`] can reach. The tip entry always survives.
    pub(crate) async fn prune(&self, pruning_boundary: Location<F>) -> Result<(), Error<F>> {
        let _guard = self.sync_lock.lock().await;
        self.check_import_persisted()?;

        let bounds = self.journal.reader().await.bounds();
        if bounds.is_empty() {
            return Ok(());
        }
        // Clamp below the tip so the journal never empties: the tip is the current state.
        let pos = self
            .first_at_or_above(pruning_boundary)
            .await?
            .min(bounds.end - 1);
        self.journal.prune(pos).await?;
        self.journal.sync().await?;
        Ok(())
    }

    /// Reject operations on a journal whose contents an unpersisted compact-sync import is
    /// about to replace.
    fn check_import_persisted(&self) -> Result<(), Error<F>> {
        if self.import_pending.load(Ordering::Relaxed) {
            return Err(Error::DataCorrupted("compact-sync import not persisted"));
        }
        Ok(())
    }

    /// Find the journal position of the entry committing exactly `target` leaves, or `None`
    /// if no retained entry does.
    async fn position_of(&self, target: Location<F>) -> Result<Option<u64>, Error<F>> {
        let pos = self.first_at_or_above(target).await?;
        let reader = self.journal.reader().await;
        if pos >= reader.bounds().end {
            return Ok(None);
        }
        let entry = reader.read(pos).await?;
        Ok((entry.proof.leaves == target).then_some(pos))
    }

    /// Binary search for the first retained position whose entry commits at least `leaf_count`
    /// leaves, or the end of the journal if none does.
    async fn first_at_or_above(&self, leaf_count: Location<F>) -> Result<u64, Error<F>> {
        let reader = self.journal.reader().await;
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

    /// Append an entry to the journal and sync it.
    async fn append_and_sync(&self, entry: &WitnessEntry<F, D>) -> Result<(), Error<F>> {
        self.journal.append(entry).await?;
        self.journal.sync().await?;
        Ok(())
    }

    /// Destroy all persisted witness state.
    pub(crate) async fn destroy(self) -> Result<(), Error<F>> {
        self.journal.destroy().await?;
        Ok(())
    }
}

/// Build a witness for the last commit from the current unpruned Merkle state.
///
/// This must run before the Merkle is pruned to its frontier, because the single-leaf inclusion proof is
/// only computable while the proof path is still retained.
fn build_witness<F, H, S>(
    merkle: &compact::Merkle<F, H::Digest, S>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<Witness<F, H::Digest>, Error<F>>
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
        let last_commit_proof = mem.proof(&hasher, last_commit_loc, inactive_peaks)?;
        Ok(Witness {
            root,
            leaf_count,
            pinned_nodes,
            last_commit_op_bytes,
            last_commit_proof,
        })
    })
}

/// Validate that a decoded commit floor does not point past the commit it authenticates.
///
/// The inactivity floor of a commit must sit at or below the commit's own location. A higher
/// floor would reference operations that do not exist yet, which indicates either disk corruption
/// when reloading a persisted witness or malformed compact-sync input when validating reconstructed
/// state from a remote source.
pub(crate) fn validate_inactivity_floor<F: Family>(
    inactivity_floor_loc: Location<F>,
    last_commit_loc: Location<F>,
) -> Result<(), Error<F>> {
    if inactivity_floor_loc > last_commit_loc {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }
    Ok(())
}

/// Build a witness from compact state that was already authenticated by the caller.
pub(crate) fn witness_from_authenticated_state<F, D, S>(
    merkle: &compact::Merkle<F, D, S>,
    root: D,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
    last_commit_proof: Proof<F, D>,
    pinned_nodes: Vec<D>,
) -> Result<Witness<F, D>, Error<F>>
where
    F: Family,
    D: Digest,
    S: Strategy,
{
    if last_commit_op_bytes.len() > MAX_OP_BYTES {
        return Err(Error::CommitTooLarge(
            last_commit_op_bytes.len(),
            MAX_OP_BYTES,
        ));
    }
    if merkle.leaves() == 0 {
        return Err(Error::DataCorrupted("missing final commit"));
    }
    let leaf_count = merkle.leaves();
    let last_commit_loc = Location::<F>::new(*leaf_count - 1);
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
    Ok(Witness {
        root,
        leaf_count,
        pinned_nodes,
        last_commit_op_bytes,
        last_commit_proof,
    })
}

/// Load the tip witness from the journal and rebuild the Merkle from it.
///
/// The tip entry is a complete snapshot: the Merkle is reset to its `(leaf_count, pinned_nodes)`,
/// the root is recomputed from the rebuilt frontier, and the persisted proof is verified against
/// that root before anything is served.
async fn load_tip<E, F, H, S, Op>(
    journal: &Journal<E, F, H::Digest>,
    merkle: &compact::Merkle<F, H::Digest, S>,
    commit_codec_config: &Op::Cfg,
    last_commit_floor: impl FnOnce(&Op) -> Option<Location<F>>,
) -> Result<(Witness<F, H::Digest>, Op), Error<F>>
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

    let WitnessEntry {
        op_bytes: last_commit_op_bytes,
        proof: last_commit_proof,
        pinned_nodes,
    } = entry;
    let leaf_count = last_commit_proof.leaves;
    if leaf_count == 0 {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }

    // Decode the commit op to get the inactivity floor, which determines the inactive peak
    // boundary used for root computation.
    let last_commit_loc = Location::new(*leaf_count - 1);
    let last_commit_op = Op::decode_cfg(last_commit_op_bytes.as_ref(), commit_codec_config)
        .map_err(|_| Error::DataCorrupted("invalid commit operation"))?;
    let inactivity_floor_loc = last_commit_floor(&last_commit_op)
        .ok_or(Error::DataCorrupted("last operation was not a commit"))?;
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;

    merkle
        .reset_to(leaf_count, pinned_nodes.clone())
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    let inactive_peaks =
        F::inactive_peaks(F::location_to_position(leaf_count), inactivity_floor_loc);
    let hasher = qmdb::hasher::<H>();
    let root = merkle
        .root(&hasher, inactive_peaks)
        .map_err(|_| Error::DataCorrupted("failed to compute compact witness root"))?;
    if !last_commit_proof.verify_range_inclusion(
        &hasher,
        &[last_commit_op_bytes.as_slice()],
        last_commit_loc,
        &root,
    ) {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }
    let witness = Witness {
        root,
        leaf_count,
        pinned_nodes,
        last_commit_op_bytes,
        last_commit_proof,
    };
    Ok((witness, last_commit_op))
}

/// Open the witness store for an existing or new compact db.
///
/// Fresh compact databases begin with exactly one committed operation: the initial commit. This
/// inserts that commit into the compact Merkle, builds its one-leaf proof, and persists the
/// resulting witness so later reopen and rewind paths use the same recovery logic as every
/// subsequent commit. An existing db instead reloads and re-verifies its tip witness.
///
/// Returns the store together with the decoded last-commit operation.
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
    if last_commit_op_bytes.len() > MAX_OP_BYTES {
        return Err(Error::CommitTooLarge(
            last_commit_op_bytes.len(),
            MAX_OP_BYTES,
        ));
    }
    let hasher = qmdb::hasher::<H>();
    let batch = {
        let batch = merkle.new_batch().add(&hasher, &last_commit_op_bytes);
        merkle.with_mem(|mem| batch.merkleize(mem, &hasher))
    };
    merkle.apply_batch(&batch)?;

    // The initial commit has one leaf and an inactivity floor of 0.
    let witness = build_witness::<F, H, S>(merkle, Location::new(0), last_commit_op_bytes)?;
    journal.append(&WitnessEntry::from(&witness)).await?;
    journal.sync().await?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl<E: Context, F: Family, D: Digest> Store<E, F, D> {
        /// Mutate the cache in tests that intentionally corrupt witness state.
        pub(crate) fn mutate(&self, f: impl FnOnce(&mut Witness<F, D>)) {
            f(&mut self.cache.write());
        }
    }

    /// Read the tip witness entry's components. Used by db tests that tamper with persisted state.
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

    /// Append a witness entry without syncing it. Used by db tests that simulate a commit
    /// interrupted before its journal sync.
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
            .append(&WitnessEntry {
                op_bytes,
                proof,
                pinned_nodes,
            })
            .await
            .unwrap();
    }

    /// Replace the tip witness entry. Used by db tests that tamper with persisted state.
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
            .append(&WitnessEntry {
                op_bytes,
                proof,
                pinned_nodes,
            })
            .await
            .unwrap();
        journal.sync().await.unwrap();
    }
}
