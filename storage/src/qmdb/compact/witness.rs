//! Shared machinery for the compact-db compact-sync witness.
//!
//! The witness is the encoded last-commit operation together with its single-leaf inclusion proof
//! against the current root. Persisting that witness alongside the compact Merkle frontier lets a
//! compact database serve compact sync for its latest committed state without retaining the full
//! historical operation log.
//!
//! This state lives at the db layer rather than the Merkle layer because only the db knows how to
//! encode and decode the typed commit operation. Both [`crate::qmdb::immutable::CompactDb`] and
//! [`crate::qmdb::keyless::CompactDb`] keep the witness in a db-owned [`Store`] backed by a
//! contiguous variable journal, then re-verify it against the current root on every reopen and
//! rewind. If those bytes no longer describe a valid witness for the stored root, reopening fails
//! with [`Error::DataCorrupted`].
//!
//! # Journal layout and crash consistency
//!
//! Each commit appends exactly one [`WitnessEntry`] (the encoded commit op plus its inclusion
//! proof). The proof's `leaves` field self-identifies the committed leaf count, which is the key
//! used to line the journal up with the Merkle. After a successful commit the journal is pruned to
//! retain only the current and previous entries: the previous entry is the witness for the Merkle's
//! one-step rewind target.
//!
//! The Merkle's generation-pointer flip is the commit point. The witness for the committed leaf
//! count must be durable *before* that flip, because once the Merkle prunes to peaks the single-leaf
//! proof can no longer be rebuilt. So every persist (1) computes the witness from the unpruned
//! `Mem`, (2) appends it to the journal and syncs, then (3) flips the Merkle. On reopen the journal
//! tip is reconciled against the Merkle's committed leaf count: an entry that is one ahead (a commit
//! that crashed after the journal sync but before the Merkle flip) is rewound away.

use crate::{
    journal::contiguous::{variable, Reader as _},
    merkle::{compact, mem::Mem, Family, Location, Proof},
    qmdb::{self, sync::compact::Target, Error},
    Context,
};
use commonware_codec::{Decode as _, EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::sync::{AsyncMutex, RwLock};

/// Number of trailing witnesses retained in the journal: the current state plus the one-step
/// rewind target.
const RETAINED: u64 = 2;

/// Decode guard against a corrupt op-bytes length prefix; generous, since the commit carries
/// optional caller metadata.
const MAX_OP_BYTES: usize = 1 << 24;

/// Decode guard against a corrupt proof length prefix. A single-leaf proof is logarithmic in the
/// leaf count plus a bounded number of peaks, so this sits far above any real proof.
const MAX_PROOF_DIGESTS: usize = 1024;

/// Codec configuration for decoding a [`WitnessEntry`] read back from the journal.
#[derive(Clone)]
pub(crate) struct WitnessEntryCfg {
    op_bytes: RangeCfg<usize>,
    proof_digests: usize,
}

impl Default for WitnessEntryCfg {
    fn default() -> Self {
        Self {
            op_bytes: (..=MAX_OP_BYTES).into(),
            proof_digests: MAX_PROOF_DIGESTS,
        }
    }
}

/// A single durably persisted witness: the encoded last-commit operation and its inclusion proof.
///
/// The root, leaf count, and pinned frontier nodes are *not* stored; they are recomputed from the
/// Merkle on load, exactly as the in-memory cache is rebuilt.
#[derive(Clone)]
pub(crate) struct WitnessEntry<F: Family, D: Digest> {
    op_bytes: Vec<u8>,
    proof: Proof<F, D>,
}

impl<F: Family, D: Digest> EncodeSize for WitnessEntry<F, D> {
    fn encode_size(&self) -> usize {
        self.op_bytes.encode_size() + self.proof.encode_size()
    }
}

impl<F: Family, D: Digest> Write for WitnessEntry<F, D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.op_bytes.write(buf);
        self.proof.write(buf);
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
        Ok(Self { op_bytes, proof })
    }
}

/// The contiguous variable journal that backs a witness [`Store`].
pub(crate) type WitnessJournal<E, F, D> = variable::Journal<E, WitnessEntry<F, D>>;

/// In-memory snapshot of the witness currently associated with the active compact state.
///
/// Compact sync serving needs the current root, frontier pins, last commit bytes, and proof as one
/// coherent unit. Keeping them together avoids repeated re-encoding and re-proofing during
/// steady-state serving while still letting reopen/rewind rebuild it from the persisted journal.
#[derive(Clone)]
pub(crate) struct ServeState<F: Family, D: Digest> {
    /// Root committed by the current persisted frontier/witness pair.
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

impl<F: Family, D: Digest> ServeState<F, D> {
    /// Convert the cached witness into the compact-sync target this source can currently serve.
    ///
    /// Compact sources only serve their current committed tip, so the target is just the root plus
    /// the total committed leaf count.
    pub(crate) const fn target(&self) -> Target<F, D> {
        Target {
            root: self.root,
            leaf_count: self.leaf_count,
        }
    }
}

impl<F: Family, D: Digest> From<&ServeState<F, D>> for WitnessEntry<F, D> {
    fn from(witness: &ServeState<F, D>) -> Self {
        Self {
            op_bytes: witness.last_commit_op_bytes.clone(),
            proof: witness.last_commit_proof.clone(),
        }
    }
}

/// Db-owned persistent store for the compact witness: a contiguous journal plus an in-memory cache
/// of the active witness.
///
/// The cache answers steady-state compact-sync serving without touching disk; the journal is the
/// durable source of truth consulted on reopen and rewind.
pub(crate) struct Store<E: Context, F: Family, D: Digest> {
    journal: WitnessJournal<E, F, D>,
    cache: RwLock<ServeState<F, D>>,
    /// Serializes the compound persist sequence (build, append+sync, flip Merkle, prune) so that
    /// concurrent `sync` calls on a shared handle do not interleave.
    sync_lock: AsyncMutex<()>,
}

/// Open the witness journal, injecting the [`WitnessEntry`] codec config (the caller's `Config<()>`
/// carries none).
pub(crate) async fn open_journal<E, F, D>(
    context: E,
    cfg: variable::Config<()>,
) -> Result<WitnessJournal<E, F, D>, Error<F>>
where
    E: Context,
    F: Family,
    D: Digest,
{
    let cfg = variable::Config {
        partition: cfg.partition,
        items_per_section: cfg.items_per_section,
        compression: cfg.compression,
        codec_config: WitnessEntryCfg::default(),
        page_cache: cfg.page_cache,
        write_buffer: cfg.write_buffer,
    };
    Ok(variable::Journal::init(context, cfg).await?)
}

impl<E: Context, F: Family, D: Digest> Store<E, F, D> {
    /// Wrap an opened journal and a verified witness into a ready-to-serve store.
    pub(crate) fn new(journal: WitnessJournal<E, F, D>, witness: ServeState<F, D>) -> Self {
        Self {
            journal,
            cache: RwLock::new(witness),
            sync_lock: AsyncMutex::new(()),
        }
    }

    /// Read the cached witness without exposing the underlying lock to db code.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&ServeState<F, D>) -> R) -> R {
        f(&self.cache.read())
    }

    /// Replace the cached witness after the matching compact Merkle state is persisted or loaded.
    pub(crate) fn replace(&self, witness: ServeState<F, D>) {
        *self.cache.write() = witness;
    }

    /// Mutate the cache in tests that intentionally corrupt witness state.
    #[cfg(test)]
    pub(crate) fn mutate(&self, f: impl FnOnce(&mut ServeState<F, D>)) {
        f(&mut self.cache.write());
    }

    /// Persist the current compact witness, flipping the Merkle frontier in lockstep.
    ///
    /// If the cached witness already matches the Merkle's committed leaf count, that witness is
    /// already the journal tip, so this only re-flips the Merkle. Otherwise it builds a fresh
    /// witness from the unpruned Merkle, appends and syncs it (durable before the flip), flips the
    /// Merkle, refreshes the cache, and prunes the journal back to the retained tail.
    pub(crate) async fn persist<H, S>(
        &self,
        merkle: &compact::Merkle<F, E, D, S>,
        last_commit_loc: Location<F>,
        inactivity_floor_loc: Location<F>,
        last_commit_op_bytes: Vec<u8>,
    ) -> Result<(), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let _guard = self.sync_lock.lock().await;

        if self.with(|w| w.leaf_count) == merkle.leaves() {
            merkle.sync().await?;
            return Ok(());
        }

        let witness = build_serve_state::<E, F, H, S>(
            merkle,
            last_commit_loc,
            inactivity_floor_loc,
            last_commit_op_bytes,
        )?;
        flush(&self.journal, merkle, &witness).await?;
        self.replace(witness);
        Ok(())
    }

    /// Re-persist the already-verified cached witness into the journal.
    ///
    /// Used when a compact db has reconstructed and verified state from compact sync and only needs
    /// to durably record that known-good witness, without recomputing the proof from a fresh tip.
    pub(crate) async fn persist_cached<S>(
        &self,
        merkle: &compact::Merkle<F, E, D, S>,
    ) -> Result<(), Error<F>>
    where
        S: Strategy,
    {
        let _guard = self.sync_lock.lock().await;
        let witness = self.with(Clone::clone);
        flush(&self.journal, merkle, &witness).await?;
        Ok(())
    }

    /// Reload and re-verify the witness for the state the Merkle was just rewound to.
    ///
    /// The Merkle now reports the previous committed leaf count, leaving the journal tip one entry
    /// ahead. [`load_active`] drops that stale tip via the same reconciliation as reopen, so this is
    /// just a reload plus a cache refresh.
    pub(crate) async fn reload_after_rewind<H, S, C, Op>(
        &self,
        merkle: &compact::Merkle<F, E, D, S>,
        commit_codec_config: &C,
        last_commit_floor: impl FnOnce(&Op) -> Option<Location<F>>,
    ) -> Result<(ServeState<F, D>, Op), Error<F>>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
        Op: Read<Cfg = C>,
    {
        let _guard = self.sync_lock.lock().await;
        let (witness, op) = load_active::<E, F, H, S, C, Op>(
            &self.journal,
            merkle,
            commit_codec_config,
            last_commit_floor,
        )
        .await?;
        self.replace(witness.clone());
        Ok((witness, op))
    }

    /// Discard any persisted witnesses so a compact-sync reinitialization starts from a clean
    /// journal. The truncation becomes durable when the subsequent [`Self::persist_cached`] syncs.
    pub(crate) async fn reset(&self) -> Result<(), Error<F>> {
        let _guard = self.sync_lock.lock().await;
        if self.journal.size().await > 0 {
            self.journal.rewind(0).await?;
        }
        Ok(())
    }

    /// Destroy all persisted witness state.
    pub(crate) async fn destroy(self) -> Result<(), Error<F>> {
        self.journal.destroy().await?;
        Ok(())
    }
}

/// Durably append `witness`, flip the Merkle in lockstep, and prune the journal to its tail.
///
/// Appending and syncing the witness before the Merkle's generation-pointer flip is what makes the
/// proof recoverable after a crash: the flip is the commit point, and the tree is pruned to peaks
/// immediately after it. Pruning afterwards retains only the current and previous witnesses (the
/// latter is the one-step rewind target).
async fn flush<E, F, D, S>(
    journal: &WitnessJournal<E, F, D>,
    merkle: &compact::Merkle<F, E, D, S>,
    witness: &ServeState<F, D>,
) -> Result<(), Error<F>>
where
    E: Context,
    F: Family,
    D: Digest,
    S: Strategy,
{
    journal.append(&WitnessEntry::from(witness)).await?;
    journal.sync().await?;
    merkle.sync().await?;
    let size = journal.size().await;
    journal.prune(size.saturating_sub(RETAINED)).await?;
    Ok(())
}

/// Build a witness from the current unpruned Merkle state.
///
/// This must run before the Merkle is pruned to peaks, because the single-leaf inclusion proof is
/// only computable while the proof path is still retained.
fn build_serve_state<E, F, H, S>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<ServeState<F, H::Digest>, Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
{
    let hasher = qmdb::hasher::<H>();
    merkle.with_mem(|mem| {
        let leaf_count = mem.leaves();
        let inactive_peaks =
            F::inactive_peaks(F::location_to_position(leaf_count), inactivity_floor_loc);
        let root = mem.root(&hasher, inactive_peaks)?;
        let last_commit_proof = mem.proof(&hasher, last_commit_loc, inactive_peaks)?;
        Ok(ServeState {
            root,
            leaf_count,
            pinned_nodes: collect_pinned_nodes(mem, leaf_count),
            last_commit_op_bytes,
            last_commit_proof,
        })
    })
}

/// Collect the frontier peaks pinned for compact-sync serving at `leaf_count`.
fn collect_pinned_nodes<F: Family, D: Digest>(mem: &Mem<F, D>, leaf_count: Location<F>) -> Vec<D> {
    F::nodes_to_pin(leaf_count)
        .map(|pos| *mem.get_node_unchecked(pos))
        .collect()
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
#[allow(clippy::type_complexity)]
pub(crate) fn witness_from_authenticated_state<F: Family, D: Digest>(
    leaf_count: Location<F>,
    root: D,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
    last_commit_proof: Proof<F, D>,
    pinned_nodes: Vec<D>,
) -> Result<(Location<F>, ServeState<F, D>), Error<F>> {
    if leaf_count == 0 {
        return Err(Error::DataCorrupted("missing final commit"));
    }
    let last_commit_loc = Location::<F>::new(*leaf_count - 1);
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
    let witness = ServeState {
        root,
        leaf_count,
        pinned_nodes,
        last_commit_op_bytes,
        last_commit_proof,
    };
    Ok((last_commit_loc, witness))
}

/// Reconcile the journal against the Merkle's committed leaf count and load the active witness.
///
/// Drops any tip entries ahead of the Merkle's committed leaf count -- left either by a crash
/// between the journal sync and the Merkle flip, or by a rewind that stepped the Merkle back -- then
/// decodes, re-verifies, and reconstructs the active witness.
async fn load_active<E, F, H, S, C, Op>(
    journal: &WitnessJournal<E, F, H::Digest>,
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    commit_codec_config: &C,
    last_commit_floor: impl FnOnce(&Op) -> Option<Location<F>>,
) -> Result<(ServeState<F, H::Digest>, Op), Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Read<Cfg = C>,
{
    let committed = merkle.leaves();
    let entry = loop {
        let size = journal.size().await;
        if size == 0 {
            return Err(Error::DataCorrupted("missing compact witness"));
        }
        let entry = {
            let reader = journal.reader().await;
            reader.read(size - 1).await?
        };
        let entry_leaves = entry.proof.leaves;
        if entry_leaves > committed {
            journal.rewind(size - 1).await?;
            continue;
        }
        if entry_leaves != committed {
            return Err(Error::DataCorrupted("compact witness behind merkle"));
        }
        break entry;
    };

    let WitnessEntry {
        op_bytes: last_commit_op_bytes,
        proof: last_commit_proof,
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
    let witness = ServeState {
        root,
        leaf_count,
        pinned_nodes: merkle.with_mem(|mem| collect_pinned_nodes(mem, leaf_count)),
        last_commit_op_bytes,
        last_commit_proof,
    };
    Ok((witness, last_commit_op))
}

/// Open the witness store for an existing or brand-new compact db.
///
/// Fresh compact databases begin with exactly one committed operation: the initial commit. This
/// inserts that commit into the compact Merkle, builds its one-leaf proof, and persists the
/// resulting witness so later reopen and rewind paths use the same recovery logic as every
/// subsequent commit. An existing db instead reloads and re-verifies its active witness.
///
/// Returns the store together with the decoded last-commit operation.
pub(crate) async fn open<E, F, H, S, C, Op>(
    journal: WitnessJournal<E, F, H::Digest>,
    merkle: &mut compact::Merkle<F, E, H::Digest, S>,
    commit_codec_config: &C,
    initial_commit_op_bytes: Vec<u8>,
    last_commit_floor: impl FnOnce(&Op) -> Option<Location<F>>,
) -> Result<(Store<E, F, H::Digest>, Op), Error<F>>
where
    E: Context,
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: Read<Cfg = C>,
{
    if merkle.leaves() == 0 {
        bootstrap_initial_commit::<E, F, H, S>(&journal, merkle, initial_commit_op_bytes).await?;
    }
    let (witness, op) =
        load_active::<E, F, H, S, C, Op>(&journal, merkle, commit_codec_config, last_commit_floor)
            .await?;
    Ok((Store::new(journal, witness), op))
}

/// Insert and persist the initial `Commit(None, 0)` for a brand-new compact db.
async fn bootstrap_initial_commit<E, F, H, S>(
    journal: &WitnessJournal<E, F, H::Digest>,
    merkle: &mut compact::Merkle<F, E, H::Digest, S>,
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
    let witness = build_serve_state::<E, F, H, S>(
        merkle,
        Location::new(0),
        Location::new(0),
        last_commit_op_bytes,
    )?;
    flush(journal, merkle, &witness).await
}

/// Read the tip witness entry's components. Used by db tests that tamper with persisted state.
#[cfg(test)]
pub(crate) async fn tip_for_test<E, F, D>(
    journal: &WitnessJournal<E, F, D>,
) -> (Vec<u8>, Proof<F, D>)
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
    (entry.op_bytes, entry.proof)
}

/// Replace the tip witness entry. Used by db tests that tamper with persisted state.
#[cfg(test)]
pub(crate) async fn overwrite_tip_for_test<E, F, D>(
    journal: &WitnessJournal<E, F, D>,
    op_bytes: Vec<u8>,
    proof: Proof<F, D>,
) where
    E: Context,
    F: Family,
    D: Digest,
{
    let size = journal.size().await;
    journal.rewind(size - 1).await.unwrap();
    journal
        .append(&WitnessEntry { op_bytes, proof })
        .await
        .unwrap();
    journal.sync().await.unwrap();
}
