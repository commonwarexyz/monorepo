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
//! 1. Build a [`CachedServeState`] from the current in-memory tip.
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
use commonware_codec::{Decode as _, Encode as _};
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
pub(crate) struct CachedServeState<F: Family, D: Digest> {
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

impl<F: Family, D: Digest> CachedServeState<F, D> {
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
pub(crate) fn write_serve_state_metadata<E, F, D>(
    metadata: &mut Metadata<E, U64, Vec<u8>>,
    slot: u8,
    serve_state: &CachedServeState<F, D>,
) where
    E: Context,
    F: Family,
    D: Digest,
{
    metadata.put(commit_op_key(slot), serve_state.commit_op_bytes.clone());
    metadata.put(proof_key(slot), serve_state.commit_proof.encode().to_vec());
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
pub(crate) async fn load_serve_state<F, E, H, C, M, DecodeCommitOp>(
    merkle: &compact::Merkle<F, E, H::Digest>,
    commit_codec_config: &C,
    decode_commit_op: DecodeCommitOp,
) -> Result<(CachedServeState<F, H::Digest>, M, Location<F>), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    DecodeCommitOp: FnOnce(&[u8], &C) -> Result<(M, Location<F>), Error<F>>,
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
    // `usize::MAX` means "do not impose an additional digest-count limit beyond structural
    // validation while decoding this persisted proof".
    let commit_proof = Proof::<F, H::Digest>::decode_cfg(proof_bytes.as_ref(), &usize::MAX)
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
    let (last_commit_metadata, inactivity_floor_loc) =
        decode_commit_op(commit_op_bytes.as_ref(), commit_codec_config)?;
    let serve_state = CachedServeState {
        root,
        leaf_count,
        pinned_nodes,
        commit_op_bytes,
        commit_proof,
    };
    Ok((serve_state, last_commit_metadata, inactivity_floor_loc))
}

/// Bootstrap the first persisted witness for a brand-new compact db.
///
/// Fresh compact databases begin with exactly one committed operation: the initial commit. This
/// helper inserts that commit into the compact Merkle, builds its one-leaf proof, and persists the
/// resulting witness/cache pair into the active slot so later reopen and rewind paths can use the
/// same recovery logic as every subsequent commit.
pub(crate) async fn bootstrap_initial_commit<F, E, H>(
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
                Ok(CachedServeState {
                    root: batch.root(),
                    leaf_count: Location::new(1),
                    pinned_nodes: Vec::new(),
                    commit_op_bytes: commit_op_bytes.clone(),
                    commit_proof: proof.clone(),
                })
            },
            |metadata, slot, serve_state| {
                write_serve_state_metadata(metadata, slot, &serve_state);
                Ok(())
            },
        )
        .await?;
    Ok(())
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
    fn serve_state_cache(&self) -> &RwLock<CachedServeState<F, H::Digest>>;

    /// Snapshot the current in-memory witness cache for use across async persistence paths.
    fn cloned_serve_state(&self) -> CachedServeState<F, H::Digest> {
        // This cache lock is only held for a short synchronous clone/update and is never held
        // across `.await`.
        self.serve_state_cache().read().clone()
    }

    /// Replace the in-memory witness cache after successful persistence or reload.
    fn store_serve_state(&self, serve_state: CachedServeState<F, H::Digest>) {
        *self.serve_state_cache().write() = serve_state;
    }
}

/// Capture a fresh witness from the current tip, persist it with the frontier, and refresh cache.
///
/// Call this after a compact db advances locally. The proof is built from the unpruned in-memory
/// tip while `sync_with_witness` still has access to the full committed `Mem`, then the
/// resulting witness bytes are persisted into the same inactive slot as the new frontier.
pub(crate) async fn persist_with_current_witness<S, F, E, H>(source: &S) -> Result<(), Error<F>>
where
    S: WitnessSource<F, E, H>,
    F: Family,
    E: Context,
    H: Hasher,
{
    // Capture a fresh witness from the currently committed in-memory tip, then atomically persist
    // it into the inactive slot alongside the Merkle frontier.
    let hasher = StandardHasher::<H>::new();
    let last_commit_loc = source.last_commit_loc();
    let commit_op_bytes = source.encode_current_commit_op();
    let serve_state = source
        .merkle()
        .sync_with_witness(
            |mem| {
                let leaf_count = mem.leaves();
                let pinned_nodes = F::nodes_to_pin(leaf_count)
                    .map(|pos| *mem.get_node_unchecked(pos))
                    .collect::<Vec<_>>();
                let commit_proof = mem.proof(&hasher, last_commit_loc)?;
                Ok(CachedServeState {
                    root: *mem.root(),
                    leaf_count,
                    pinned_nodes,
                    commit_op_bytes: commit_op_bytes.clone(),
                    commit_proof,
                })
            },
            |metadata, slot, serve_state| {
                write_serve_state_metadata(metadata, slot, &serve_state);
                Ok(())
            },
        )
        .await?;
    source.store_serve_state(serve_state);
    Ok(())
}

/// Re-persist the already-verified cached witness into the newly active slot.
///
/// This is used when a compact db has reconstructed and verified state from persisted data and only
/// needs to move that known-good witness into the Merkle's slot layout, without recomputing the
/// proof from a fresh tip commit.
pub(crate) async fn persist_cached_serve_state<S, F, E, H>(source: &S) -> Result<(), Error<F>>
where
    S: WitnessSource<F, E, H>,
    F: Family,
    E: Context,
    H: Hasher,
{
    // Re-persist the already-verified cached witness after the Merkle slot changes (for example,
    // after root verification on compact sync initialization) without recomputing proofs.
    let serve_state = source.cloned_serve_state();
    source
        .merkle()
        .sync_with_witness(
            |_| Ok(serve_state.clone()),
            |metadata, slot, serve_state| {
                write_serve_state_metadata(metadata, slot, &serve_state);
                Ok(())
            },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
}
