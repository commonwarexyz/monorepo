//! Shared machinery for the compact-db compact-sync witness.
//!
//! The witness is the encoded last-commit operation together with its single-leaf inclusion proof
//! against the current root. Persisting that witness in the compact Merkle base log lets a
//! compact database serve compact sync for its latest committed state without retaining the full
//! historical operation log.
//!
//! This state lives at the db layer rather than the Merkle layer because only the db knows how to
//! encode and decode the typed commit operation. Both [`crate::qmdb::immutable::CompactDb`] and
//! [`crate::qmdb::keyless::CompactDb`] store the witness in the same retained base as the frontier
//! state, then re-verify it against the current root on every reopen and rewind. If those
//! bytes no longer describe a valid witness for the stored root, reopening fails with
//! [`Error::DataCorrupted`].
//!
//! The lifecycle in this file is:
//!
//! 1. Build a [`ServeState`] from the current in-memory tip.
//! 2. Persist its witness bytes into the same retained base used by the compact Merkle frontier.
//! 3. Reload that witness on reopen or rewind, re-verify it against the currently loaded root, and
//!    rebuild the cache.
//! 4. Use the cache to answer compact-sync requests without re-encoding the commit or recomputing
//!    its proof on every serve.

use crate::{
    merkle::{compact, mem::Mem, Family, Location, Proof},
    qmdb::{self, sync::compact::Target, Error},
    Context,
};
use commonware_codec::{Decode as _, Encode as _, FixedSize, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::sync::RwLock;

pub(crate) type ActiveWitness<F, D, Op> = (ServeState<F, D>, Op);

/// In-memory cache of the witness currently associated with the active compact state.
///
/// Compact sync serving needs the current root, frontier pins, last commit bytes, and proof as one
/// coherent unit. Keeping them together here avoids repeated re-encoding and re-proofing during
/// steady-state serving while still letting reopen/rewind rebuild the cache from persisted bytes.
#[derive(Clone)]
pub(crate) struct ServeState<F: Family, D: Digest> {
    /// Root committed by the current persisted frontier/witness pair.
    pub(crate) root: D,
    /// Total leaves in the committed Merkle, which also identifies the tip commit location.
    pub(crate) leaf_count: Location<F>,
    /// Inactivity floor declared by the current committed state.
    pub(crate) floor: Location<F>,
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

/// Synchronous cache for the compact witness currently safe to serve.
///
/// The cache is intentionally tiny: it only hides the lock used to read and replace the witness.
/// Higher-level persistence and serving logic stays explicit at call sites.
pub(crate) struct Cache<F: Family, D: Digest> {
    witness: RwLock<ServeState<F, D>>,
}

impl<F: Family, D: Digest> Cache<F, D> {
    /// Create a cache from the witness loaded or bootstrapped during db initialization.
    pub(crate) const fn new(witness: ServeState<F, D>) -> Self {
        Self {
            witness: RwLock::new(witness),
        }
    }

    /// Read the cached witness without exposing the underlying lock to db code.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&ServeState<F, D>) -> R) -> R {
        f(&self.witness.read())
    }

    /// Replace the cached witness after the matching compact Merkle state is persisted or loaded.
    pub(crate) fn replace(&self, witness: ServeState<F, D>) {
        *self.witness.write() = witness;
    }

    /// Mutate the cache in tests that intentionally corrupt witness state.
    #[cfg(test)]
    pub(crate) fn mutate(&self, f: impl FnOnce(&mut ServeState<F, D>)) {
        f(&mut self.witness.write());
    }
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
pub(crate) fn witness_from_authenticated_state<F, E, D, S>(
    merkle: &compact::Merkle<F, E, D, S>,
    root: D,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
    last_commit_proof: Proof<F, D>,
    pinned_nodes: Vec<D>,
) -> Result<(Location<F>, ServeState<F, D>), Error<F>>
where
    F: Family,
    E: Context,
    D: Digest,
    S: Strategy,
{
    if merkle.leaves() == 0 {
        return Err(Error::DataCorrupted("missing final commit"));
    }
    let leaf_count = merkle.leaves();
    let last_commit_loc = Location::<F>::new(*leaf_count - 1);
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
    let witness = ServeState {
        root,
        leaf_count,
        floor: inactivity_floor_loc,
        pinned_nodes,
        last_commit_op_bytes,
        last_commit_proof,
    };
    Ok((last_commit_loc, witness))
}

/// Rebuild the in-memory witness cache from the active retained base.
///
/// This is the authoritative recovery path after reopen and rewind. It:
///
/// 1. reads the active base's commit bytes and proof bytes,
/// 2. decodes the proof,
/// 3. re-verifies that proof against the Merkle currently loaded in memory,
/// 4. reconstructs the frontier pins for serving, and
/// 5. decodes the typed last commit operation needed by the caller's db state.
///
/// Any missing base data, decode failure, or proof/root mismatch is treated as
/// [`Error::DataCorrupted`], because the persisted frontier and witness no longer describe the same
/// committed state.
pub(crate) fn load_active_witness<F, E, H, S, C, Op, LastCommitFloor>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    commit_codec_config: &C,
    last_commit_floor: LastCommitFloor,
) -> Result<ActiveWitness<F, H::Digest, Op>, Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
    Op: Read<Cfg = C>,
    LastCommitFloor: FnOnce(&Op) -> Option<Location<F>>,
{
    let base = merkle
        .active_base()
        .ok_or(Error::DataCorrupted("missing compact witness"))?;
    let last_commit_op_bytes = base.last_commit_op_bytes.clone();
    let last_commit_proof_bytes = base.last_commit_proof_bytes.clone();
    // Every encoded digest is at least `D::SIZE` bytes on the wire, so `proof_bytes.len() /
    // D::SIZE` is a hard upper bound on the digest count. Using this as the decode cap prevents a
    // malformed length prefix from forcing a large preallocation.
    let max_digests = last_commit_proof_bytes.len() / H::Digest::SIZE;
    let last_commit_proof =
        Proof::<F, H::Digest>::decode_cfg(last_commit_proof_bytes.as_ref(), &max_digests)
            .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
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
    if inactivity_floor_loc != base.floor {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }

    let inactive_peaks =
        F::inactive_peaks(F::location_to_position(leaf_count), inactivity_floor_loc);
    let hasher = qmdb::hasher::<H>();
    let root = merkle
        .root(&hasher, inactive_peaks)
        .map_err(|_| Error::DataCorrupted("failed to compute compact witness root"))?;
    if root != base.root {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }
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
        floor: inactivity_floor_loc,
        pinned_nodes: base.pinned_nodes,
        last_commit_op_bytes,
        last_commit_proof,
    };
    Ok((witness, last_commit_op))
}

/// Bootstrap the first persisted witness for a brand-new compact db.
///
/// Fresh compact databases begin with exactly one committed operation: the initial commit. This
/// helper inserts that commit into the compact Merkle, builds its one-leaf proof, and persists the
/// resulting witness into the active slot so later reopen and rewind paths can use the
/// same recovery logic as every subsequent commit.
pub(crate) async fn bootstrap_initial_commit<F, E, H, S>(
    merkle: &mut compact::Merkle<F, E, H::Digest, S>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    let hasher = qmdb::hasher::<H>();
    let batch = {
        let batch = merkle.new_batch().add(&hasher, &last_commit_op_bytes);
        merkle.with_mem(|mem| batch.merkleize(mem, &hasher))
    };
    merkle.apply_batch(&batch)?;

    // The initial commit has one leaf and an inactivity floor of 0, giving 0 inactive peaks.
    let leaf_count = merkle.leaves();
    let inactive_peaks = F::inactive_peaks(F::location_to_position(leaf_count), Location::new(0));
    merkle
        .sync_with_witness(
            |mem| {
                let root = mem.root(&hasher, inactive_peaks)?;
                let last_commit_proof = mem.proof(&hasher, Location::new(0), inactive_peaks)?;
                Ok(ServeState {
                    root,
                    leaf_count: Location::new(1),
                    floor: Location::new(0),
                    pinned_nodes: Vec::new(),
                    last_commit_op_bytes: last_commit_op_bytes.clone(),
                    last_commit_proof,
                })
            },
            |leaf_count, pinned_nodes, witness| {
                let mut witness = witness;
                witness.leaf_count = leaf_count;
                witness.pinned_nodes = pinned_nodes.clone();
                Ok((
                    compact::Base {
                        root: witness.root,
                        leaf_count,
                        floor: witness.floor,
                        pinned_nodes,
                        last_commit_op_bytes: witness.last_commit_op_bytes.clone(),
                        last_commit_proof_bytes: witness.last_commit_proof.encode().to_vec(),
                    },
                    (),
                ))
            },
        )
        .await?;
    Ok(())
}

/// Persist the current compact witness for a compact db.
///
/// If the cached witness already matches the Merkle leaf count being synced, it is copied into
/// the Merkle slot being activated. Otherwise, a new witness is built from the unpruned Merkle
/// before sync prunes it. The cache check runs inside `sync_with_witness` so concurrent syncs
/// observe the latest witness cache after each persisted slot flip.
enum PersistMode {
    Write,
    Commit,
    SyncStart,
    Sync,
}

async fn persist_witness<F, E, H, S>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    cache: &Cache<F, H::Digest>,
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
    mode: PersistMode,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    let hasher = qmdb::hasher::<H>();
    let build_witness = |mem: &Mem<F, H::Digest>| {
        let mem_leaves = mem.leaves();
        if let Some(cached) =
            cache.with(|witness| (witness.leaf_count == mem_leaves).then(|| witness.clone()))
        {
            return Ok(cached);
        }
        let inactive_peaks =
            F::inactive_peaks(F::location_to_position(mem_leaves), inactivity_floor_loc);
        let mem_root = mem.root(&hasher, inactive_peaks)?;
        let pinned_nodes = F::nodes_to_pin(mem_leaves)
            .map(|pos| *mem.get_node_unchecked(pos))
            .collect::<Vec<_>>();
        let last_commit_proof = mem.proof(&hasher, last_commit_loc, inactive_peaks)?;
        Ok(ServeState {
            root: mem_root,
            leaf_count: mem_leaves,
            floor: inactivity_floor_loc,
            pinned_nodes,
            last_commit_op_bytes: last_commit_op_bytes.clone(),
            last_commit_proof,
        })
    };
    let build_base = |leaf_count, pinned_nodes: Vec<H::Digest>, witness: ServeState<F, H::Digest>| {
        let mut witness = witness;
        witness.leaf_count = leaf_count;
        witness.pinned_nodes = pinned_nodes.clone();
        let base = compact::Base {
            root: witness.root,
            leaf_count,
            floor: witness.floor,
            pinned_nodes,
            last_commit_op_bytes: witness.last_commit_op_bytes.clone(),
            last_commit_proof_bytes: witness.last_commit_proof.encode().to_vec(),
        };
        cache.replace(witness);
        Ok((base, ()))
    };

    match mode {
        PersistMode::Write => {
            merkle
                .write_with_witness(build_witness, build_base)
                .await?;
        }
        PersistMode::Commit => {
            merkle
                .commit_with_witness(build_witness, build_base)
                .await?;
        }
        PersistMode::SyncStart => {
            merkle
                .sync_start_with_witness(build_witness, build_base)
                .await?;
        }
        PersistMode::Sync => {
            merkle
                .sync_with_witness(build_witness, build_base)
                .await?;
        }
    }
    Ok(())
}

/// Write the current compact witness without calling journal commit or sync.
pub(crate) async fn write_witness<F, E, H, S>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    cache: &Cache<F, H::Digest>,
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    persist_witness::<F, E, H, S>(
        merkle,
        cache,
        last_commit_loc,
        inactivity_floor_loc,
        last_commit_op_bytes,
        PersistMode::Write,
    )
    .await
}

/// Commit the current compact witness through the retained-base journal commit path.
pub(crate) async fn commit_witness<F, E, H, S>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    cache: &Cache<F, H::Digest>,
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    persist_witness::<F, E, H, S>(
        merkle,
        cache,
        last_commit_loc,
        inactivity_floor_loc,
        last_commit_op_bytes,
        PersistMode::Commit,
    )
    .await
}

/// Start syncing the current compact witness without waiting for durability.
pub(crate) async fn sync_start_witness<F, E, H, S>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    cache: &Cache<F, H::Digest>,
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    persist_witness::<F, E, H, S>(
        merkle,
        cache,
        last_commit_loc,
        inactivity_floor_loc,
        last_commit_op_bytes,
        PersistMode::SyncStart,
    )
    .await
}

/// Durably sync the current compact witness.
pub(crate) async fn sync_witness<F, E, H, S>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    cache: &Cache<F, H::Digest>,
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    persist_witness::<F, E, H, S>(
        merkle,
        cache,
        last_commit_loc,
        inactivity_floor_loc,
        last_commit_op_bytes,
        PersistMode::Sync,
    )
    .await
}

/// Build a serving witness from the current in-memory compact Merkle state
/// without persisting it.
///
/// This lets a compact db serve its live post-apply target before the
/// background durability sync has committed the corresponding retained base.
pub(crate) fn live_witness<F, E, H, S>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    last_commit_loc: Location<F>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<ServeState<F, H::Digest>, Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    let hasher = qmdb::hasher::<H>();
    merkle.with_mem(|mem| {
        let leaf_count = mem.leaves();
        if leaf_count == 0 {
            return Err(Error::DataCorrupted("missing final commit"));
        }
        if Location::new(*leaf_count - 1) != last_commit_loc {
            return Err(Error::DataCorrupted("invalid compact witness"));
        }
        validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
        let inactive_peaks =
            F::inactive_peaks(F::location_to_position(leaf_count), inactivity_floor_loc);
        let root = mem.root(&hasher, inactive_peaks)?;
        let pinned_nodes = F::nodes_to_pin(leaf_count)
            .map(|pos| *mem.get_node_unchecked(pos))
            .collect();
        let last_commit_proof = mem.proof(&hasher, last_commit_loc, inactive_peaks)?;
        Ok(ServeState {
            root,
            leaf_count,
            floor: inactivity_floor_loc,
            pinned_nodes,
            last_commit_op_bytes,
            last_commit_proof,
        })
    })
}

/// Re-persist the already-verified cached witness into the retained-base log.
///
/// This is used when a compact db has reconstructed and verified state from persisted data and only
/// needs to move that known-good witness into the Merkle's base log, without recomputing the
/// proof from a fresh tip commit.
pub(crate) async fn persist_cached_witness<F, E, H, S>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    cache: &Cache<F, H::Digest>,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    // Re-persist the already-verified cached witness after the Merkle slot changes (for example,
    // after root verification on compact sync initialization) without recomputing proofs.
    let witness = cache.with(Clone::clone);
    merkle
        .sync_with_witness(
            |_| Ok(witness),
            |leaf_count, pinned_nodes, witness| {
                Ok((
                    compact::Base {
                        root: witness.root,
                        leaf_count,
                        floor: witness.floor,
                        pinned_nodes,
                        last_commit_op_bytes: witness.last_commit_op_bytes.clone(),
                        last_commit_proof_bytes: witness.last_commit_proof.encode().to_vec(),
                    },
                    (),
                ))
            },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
}
