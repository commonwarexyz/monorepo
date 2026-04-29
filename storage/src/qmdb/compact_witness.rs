//! Shared machinery for the compact-db compact-sync witness.
//!
//! The witness is the encoded last-commit operation together with its single-leaf inclusion proof
//! against the current root. Persisting that witness alongside the compact Merkle frontier lets a
//! compact database serve compact sync for its latest committed state without retaining the full
//! historical operation log.
//!
//! This state lives at the db layer rather than the Merkle layer because only the db knows how to
//! encode and decode the typed commit operation. Both [`crate::qmdb::immutable::CompactDb`] and
//! [`crate::qmdb::keyless::CompactDb`] store the witness in the same ping-pong slots as the
//! frontier state, then re-verify it against the current root on every reopen and rewind. If those
//! bytes no longer describe a valid witness for the stored root, reopening fails with
//! [`Error::DataCorrupted`].
//!
//! The lifecycle in this file is:
//!
//! 1. Build a [`Witness`] from the current in-memory tip.
//! 2. Persist its witness bytes into the same active/inactive slot scheme used by the compact
//!    Merkle frontier.
//! 3. Reload that witness on reopen or rewind, re-verify it against the currently loaded root, and
//!    rebuild the cache.
//! 4. Use the cache to answer compact-sync requests without re-encoding the commit or recomputing
//!    its proof on every serve.

use crate::{
    merkle::{compact, hasher::Standard as StandardHasher, Family, Location, Proof, Readable},
    metadata::Metadata,
    qmdb::{sync::compact::Target, Error},
    Context,
};
use commonware_codec::{Decode as _, Encode, FixedSize, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_utils::{sequence::prefixed_u64::U64, sync::RwLock};

// Per-slot db-extra layout. A "slot" is one side of the compact Merkle's ping-pong persistence
// scheme: each sync writes the next committed state into the inactive slot and then flips which
// slot is active. Slots 0-4 belong to the Merkle layer; slots 5-8 mirror that scheme for the
// db-level compact-sync witness. Only the active slot is ever consulted on reopen, rewind, or
// serving; stale witness bytes left behind in the inactive slot are harmless until the next sync
// overwrites them.
//   (5, 0) slot A commit op bytes     (7, 0) slot B commit op bytes
//   (6, 0) slot A commit proof bytes  (8, 0) slot B commit proof bytes
const SLOT_A_COMMIT_OP_PREFIX: u8 = 5;
const SLOT_A_PROOF_PREFIX: u8 = 6;
const SLOT_B_COMMIT_OP_PREFIX: u8 = 7;
const SLOT_B_PROOF_PREFIX: u8 = 8;

/// Return the metadata prefix used for commit-op bytes in the given ping-pong slot.
const fn commit_op_prefix(slot: u8) -> u8 {
    if slot == 0 {
        SLOT_A_COMMIT_OP_PREFIX
    } else {
        SLOT_B_COMMIT_OP_PREFIX
    }
}

/// Return the metadata prefix used for proof bytes in the given ping-pong slot.
const fn proof_prefix(slot: u8) -> u8 {
    if slot == 0 {
        SLOT_A_PROOF_PREFIX
    } else {
        SLOT_B_PROOF_PREFIX
    }
}

/// Metadata key for the encoded last-commit operation in `slot`.
pub(crate) const fn commit_op_key(slot: u8) -> U64 {
    U64::new(commit_op_prefix(slot), 0)
}

/// Metadata key for the last-commit inclusion proof in `slot`.
pub(crate) const fn proof_key(slot: u8) -> U64 {
    U64::new(proof_prefix(slot), 0)
}

/// In-memory cache of the witness currently associated with the active compact state.
///
/// Compact sync serving needs the current root, frontier pins, last commit bytes, and proof as one
/// coherent unit. Keeping them together here avoids repeated re-encoding and re-proofing during
/// steady-state serving while still letting reopen/rewind rebuild the cache from persisted bytes.
#[derive(Clone)]
pub(crate) struct Witness<F: Family, D: Digest> {
    /// Root committed by the current persisted frontier/witness pair.
    pub(crate) root: D,
    /// Total leaves in the committed Merkle, which also identifies the tip commit location.
    pub(crate) leaf_count: Location<F>,
    /// Frontier nodes pinned by compact sync; these are the persisted peaks, not the proof path.
    pub(crate) pinned_nodes: Vec<D>,
    /// Encoded last-commit operation bytes used for root verification and serving.
    pub(crate) commit_op_bytes: Vec<u8>,
    /// Inclusion proof for the last-commit leaf against `root`.
    pub(crate) commit_proof: Proof<F, D>,
}

impl<F: Family, D: Digest> Witness<F, D> {
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

/// Write the witness portion of `serve_state` into the given ping-pong slot's db metadata.
///
/// The compact Merkle layer persists the frontier itself. This helper persists the db-owned
/// witness bytes that must move in lockstep with that frontier.
pub(crate) fn write_witness_metadata<E, F, D>(
    metadata: &mut Metadata<E, U64, Vec<u8>>,
    slot: u8,
    serve_state: &Witness<F, D>,
) where
    E: Context,
    F: Family,
    D: Digest,
{
    metadata.put(commit_op_key(slot), serve_state.commit_op_bytes.clone());
    metadata.put(proof_key(slot), serve_state.commit_proof.encode().to_vec());
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

/// `(metadata, inactivity_floor)` extracted from a commit operation.
type CommitFields<Op> = (
    Option<<Op as CompactCommit>::Metadata>,
    Location<<Op as CompactCommit>::Family>,
);

/// `(serve cache, last commit metadata, inactivity floor)` rebuilt from a persisted witness.
type LoadedWitness<F, D, M> = (Witness<F, D>, Option<M>, Location<F>);

/// Commit operation behavior needed by compact witnesses.
pub(crate) trait CompactCommit: Sized {
    type Family: Family;
    type Metadata: Clone;
    type CommitCfg: Clone + Send + Sync + 'static;

    /// Build a commit op with the given metadata and inactivity floor.
    fn build_commit(metadata: Option<Self::Metadata>, floor: Location<Self::Family>) -> Self;

    /// Whether this op is a commit. Used by the compact-serving path to validate the shape of
    /// a decoded op without consuming it (so the typed op can still be returned to callers).
    fn is_commit(&self) -> bool;

    /// Extract `(metadata, inactivity_floor)` if this op is a commit; otherwise return `None`.
    fn into_commit_fields(self) -> Option<CommitFields<Self>>;
}

/// Rebuild the in-memory serve cache from the active slot's persisted witness.
///
/// This is the authoritative recovery path after reopen and rewind. It:
///
/// 1. reads the active slot's commit bytes and proof bytes,
/// 2. decodes the proof,
/// 3. re-verifies that proof against the Merkle currently loaded in memory,
/// 4. reconstructs the frontier pins for serving, and
/// 5. decodes the typed commit fields needed by the caller's db state.
///
/// Any missing metadata, decode failure, or proof/root mismatch is treated as
/// [`Error::DataCorrupted`], because the persisted frontier and witness no longer describe the same
/// committed state.
pub(crate) async fn load_active_witness<F, E, H, Op>(
    merkle: &compact::Merkle<F, E, H::Digest>,
    commit_codec_config: &Op::CommitCfg,
) -> Result<LoadedWitness<F, H::Digest, Op::Metadata>, Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    Op: CompactCommit<Family = F> + Read<Cfg = Op::CommitCfg>,
{
    let slot = merkle.active_slot();
    let commit_op_bytes = merkle
        .read_metadata_key(&commit_op_key(slot))
        .await
        .ok_or(Error::DataCorrupted("missing compact witness"))?;
    let proof_bytes = merkle
        .read_metadata_key(&proof_key(slot))
        .await
        .ok_or(Error::DataCorrupted("missing compact witness"))?;
    // Every encoded digest is at least `D::SIZE` bytes on the wire, so `proof_bytes.len() /
    // D::SIZE` is a hard upper bound on the digest count. Using this as the decode cap prevents a
    // malformed length prefix from forcing a large preallocation.
    let max_digests = proof_bytes.len() / H::Digest::SIZE;
    let commit_proof = Proof::<F, H::Digest>::decode_cfg(proof_bytes.as_ref(), &max_digests)
        .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    let root = merkle.root();
    let leaf_count = commit_proof.leaves;
    if leaf_count == 0 {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }
    let last_commit_loc = Location::new(*leaf_count - 1);
    let hasher = StandardHasher::<H>::new();
    if !commit_proof.verify_element_inclusion(
        &hasher,
        commit_op_bytes.as_slice(),
        last_commit_loc,
        &root,
    ) {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }
    let pinned_nodes = merkle.with_mem(|mem| {
        F::nodes_to_pin(leaf_count)
            .map(|pos| *mem.get_node_unchecked(pos))
            .collect::<Vec<_>>()
    });
    let op = Op::decode_cfg(commit_op_bytes.as_ref(), commit_codec_config)
        .map_err(|_| Error::DataCorrupted("invalid persisted commit operation"))?;
    let (last_commit_metadata, inactivity_floor_loc) = op.into_commit_fields().ok_or(
        Error::DataCorrupted("persisted last operation was not a commit"),
    )?;
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
    let serve_state = Witness {
        root,
        leaf_count,
        pinned_nodes,
        commit_op_bytes,
        commit_proof,
    };
    Ok((serve_state, last_commit_metadata, inactivity_floor_loc))
}

/// Validate caller-supplied compact-sync state and assemble it into a serve cache.
///
/// Used on the compact-sync init path where the caller has already authenticated the supplied
/// commit proof against the requested target root, but the leaf count and floor still need to be
/// checked locally. Returns `(last_commit_loc, cache)`.
#[allow(clippy::type_complexity)]
pub(crate) fn validate_witness<F, D>(
    root: D,
    leaf_count: Location<F>,
    inactivity_floor_loc: Location<F>,
    commit_op_bytes: Vec<u8>,
    commit_proof: Proof<F, D>,
    pinned_nodes: Vec<D>,
) -> Result<(Location<F>, Witness<F, D>), Error<F>>
where
    F: Family,
    D: Digest,
{
    if leaf_count == 0 {
        return Err(Error::DataCorrupted("missing final commit"));
    }
    let last_commit_loc = Location::<F>::new(*leaf_count - 1);
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
    let serve_state = Witness {
        root,
        leaf_count,
        pinned_nodes,
        commit_op_bytes,
        commit_proof,
    };
    Ok((last_commit_loc, serve_state))
}

/// Bootstrap the first persisted witness for a brand-new compact db.
///
/// Fresh compact databases begin with exactly one committed operation: the initial commit. This
/// helper inserts that commit into the compact Merkle, builds its one-leaf proof, and persists the
/// resulting witness/cache pair into the active slot so later reopen and rewind paths can use the
/// same recovery logic as every subsequent commit.
async fn bootstrap_initial_commit<F, E, H>(
    merkle: &mut compact::Merkle<F, E, H::Digest>,
    commit_op_bytes: Vec<u8>,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
{
    let hasher = StandardHasher::<H>::new();
    let batch = {
        let batch = merkle.new_batch().add(&hasher, &commit_op_bytes);
        merkle.with_mem(|mem| batch.merkleize(mem, &hasher))
    };
    let proof = batch.proof(&hasher, Location::new(0))?;
    merkle.apply_batch(&batch)?;
    merkle
        .sync_with_witness(
            |_| {
                Ok(Witness {
                    root: batch.root(),
                    leaf_count: Location::new(1),
                    pinned_nodes: Vec::new(),
                    commit_op_bytes: commit_op_bytes.clone(),
                    commit_proof: proof.clone(),
                })
            },
            |metadata, slot, serve_state| {
                write_witness_metadata(metadata, slot, &serve_state);
                Ok(())
            },
        )
        .await?;
    Ok(())
}

/// Open a compact db's persisted witness, bootstrapping an initial commit on first open.
///
/// Returns the cached serve state plus the typed last-commit fields the caller needs to populate
/// its own in-memory state. After this returns, the active slot is guaranteed to have a servable
/// frontier/witness pair, so later reopen and rewind paths can assume that invariant.
pub(crate) async fn init_compact_state<F, E, H, Op>(
    merkle: &mut compact::Merkle<F, E, H::Digest>,
    commit_codec_config: &Op::CommitCfg,
) -> Result<LoadedWitness<F, H::Digest, Op::Metadata>, Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    Op: CompactCommit<Family = F> + Encode + Read<Cfg = Op::CommitCfg>,
{
    if merkle.leaves() == 0 {
        let initial_floor = Location::new(0);
        let commit_op_bytes = Op::build_commit(None, initial_floor).encode().to_vec();
        bootstrap_initial_commit::<F, E, H>(merkle, commit_op_bytes).await?;
    }
    load_active_witness::<F, E, H, Op>(merkle, commit_codec_config).await
}

// Shared hook for persisting and reloading the current servable witness for compact immutable and
// keyless databases.
//
// This trait is intentionally narrow. It is not trying to abstract "all compact databases"; it
// only centralizes the small amount of logic needed to capture, cache, persist, and restore the
// authenticated tip witness that compact sync serves.
pub(crate) trait WitnessSource<F, E, H>
where
    F: Family,
    E: Context,
    H: Hasher,
{
    /// Return the compact Merkle whose active slot is authoritative for this db.
    fn merkle(&self) -> &compact::Merkle<F, E, H::Digest>;

    /// Return the location of the current tip commit in that Merkle.
    fn last_commit_loc(&self) -> Location<F>;

    /// Encode the current tip commit exactly as it should be persisted and later served.
    fn encode_current_commit_op(&self) -> Vec<u8>;

    /// Return the in-memory cache for the currently servable witness.
    fn witness_cache(&self) -> &RwLock<Witness<F, H::Digest>>;

    /// Snapshot the current in-memory witness cache for use across async persistence paths.
    fn cloned_witness(&self) -> Witness<F, H::Digest> {
        // This cache lock is only held for a short synchronous clone/update and is never held
        // across `.await`.
        self.witness_cache().read().clone()
    }

    /// Replace the in-memory witness cache after successful persistence or reload.
    fn store_witness(&self, serve_state: Witness<F, H::Digest>) {
        *self.witness_cache().write() = serve_state;
    }
}

/// Persist the current servable witness for a compact db, picking between fresh and cached paths.
///
/// Matching cached state is re-persisted without rebuilding a proof, since compact `Mem` may
/// already be pruned to peaks. The cache check runs inside `sync_with_witness` so concurrent syncs
/// observe the latest cache after each persisted slot flip.
pub(crate) async fn persist_witness<S, F, E, H>(source: &S) -> Result<(), Error<F>>
where
    S: WitnessSource<F, E, H>,
    F: Family,
    E: Context,
    H: Hasher,
{
    let hasher = StandardHasher::<H>::new();
    let last_commit_loc = source.last_commit_loc();
    let commit_op_bytes = source.encode_current_commit_op();
    source
        .merkle()
        .sync_with_witness(
            |mem| {
                let cached = source.cloned_witness();
                let mem_root = *mem.root();
                let mem_leaves = mem.leaves();
                if cached.root == mem_root && cached.leaf_count == mem_leaves {
                    return Ok(cached);
                }
                let pinned_nodes = F::nodes_to_pin(mem_leaves)
                    .map(|pos| *mem.get_node_unchecked(pos))
                    .collect::<Vec<_>>();
                let commit_proof = mem.proof(&hasher, last_commit_loc)?;
                Ok(Witness {
                    root: mem_root,
                    leaf_count: mem_leaves,
                    pinned_nodes,
                    commit_op_bytes: commit_op_bytes.clone(),
                    commit_proof,
                })
            },
            |metadata, slot, serve_state| {
                write_witness_metadata(metadata, slot, &serve_state);
                source.store_witness(serve_state.clone());
                Ok(())
            },
        )
        .await?;
    Ok(())
}

/// Re-persist the already-verified cached witness into the newly active slot.
///
/// This is used when a compact db has reconstructed and verified state from persisted data and only
/// needs to move that known-good witness into the Merkle's slot layout, without recomputing the
/// proof from a fresh tip commit.
pub(crate) async fn persist_cached_witness<S, F, E, H>(source: &S) -> Result<(), Error<F>>
where
    S: WitnessSource<F, E, H>,
    F: Family,
    E: Context,
    H: Hasher,
{
    // Re-persist the already-verified cached witness after the Merkle slot changes (for example,
    // after root verification on compact sync initialization) without recomputing proofs.
    let serve_state = source.cloned_witness();
    source
        .merkle()
        .sync_with_witness(
            |_| Ok(serve_state.clone()),
            |metadata, slot, serve_state| {
                write_witness_metadata(metadata, slot, &serve_state);
                Ok(())
            },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
}
