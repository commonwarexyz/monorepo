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
    qmdb::{
        sync::compact::{State, Target},
        Error,
    },
    Context,
};
use commonware_codec::{Decode as _, Encode as _, FixedSize, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{sequence::prefixed_u64::U64, sync::RwLock};

// Per-slot db-extra layout. A "slot" is one side of the compact Merkle's ping-pong persistence
// scheme: each sync writes the next committed state into the inactive slot and then flips which
// slot is active. Slots 0-4 belong to the Merkle layer; slots 5-8 mirror that scheme for the
// db-level compact-sync witness. Only the active slot is ever consulted on reopen, rewind, or
// serving; stale witness bytes left behind in the inactive slot are harmless until the next sync
// overwrites them.
//   (5, 0) slot A last commit op bytes     (7, 0) slot B last commit op bytes
//   (6, 0) slot A last commit proof bytes  (8, 0) slot B last commit proof bytes
const SLOT_A_LAST_COMMIT_OP_PREFIX: u8 = 5;
const SLOT_A_LAST_COMMIT_PROOF_PREFIX: u8 = 6;
const SLOT_B_LAST_COMMIT_OP_PREFIX: u8 = 7;
const SLOT_B_LAST_COMMIT_PROOF_PREFIX: u8 = 8;

/// Return the metadata prefix used for last-commit op bytes in the given ping-pong slot.
const fn last_commit_op_prefix(slot: u8) -> u8 {
    if slot == 0 {
        SLOT_A_LAST_COMMIT_OP_PREFIX
    } else {
        SLOT_B_LAST_COMMIT_OP_PREFIX
    }
}

/// Return the metadata prefix used for last-commit proof bytes in the given ping-pong slot.
const fn last_commit_proof_prefix(slot: u8) -> u8 {
    if slot == 0 {
        SLOT_A_LAST_COMMIT_PROOF_PREFIX
    } else {
        SLOT_B_LAST_COMMIT_PROOF_PREFIX
    }
}

/// Metadata key for the encoded last-commit operation in `slot`.
pub(crate) const fn last_commit_op_key(slot: u8) -> U64 {
    U64::new(last_commit_op_prefix(slot), 0)
}

/// Metadata key for the last-commit inclusion proof in `slot`.
pub(crate) const fn last_commit_proof_key(slot: u8) -> U64 {
    U64::new(last_commit_proof_prefix(slot), 0)
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
    pub(crate) last_commit_op_bytes: Vec<u8>,
    /// Inclusion proof for the last-commit leaf against `root`.
    pub(crate) last_commit_proof: Proof<F, D>,
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

    /// Convert the witness into compact-sync protocol state.
    pub(crate) fn to_state<Op, C>(
        &self,
        codec_config: &C,
        is_commit: impl FnOnce(&Op) -> bool,
    ) -> Result<State<F, Op, D>, Error<F>>
    where
        Op: Read<Cfg = C>,
    {
        let op = Op::decode_cfg(self.last_commit_op_bytes.as_ref(), codec_config)
            .map_err(|_| Error::DataCorrupted("invalid commit operation"))?;
        if !is_commit(&op) {
            return Err(Error::DataCorrupted("last operation was not a commit"));
        }

        Ok(State {
            leaf_count: self.leaf_count,
            pinned_nodes: self.pinned_nodes.clone(),
            last_commit_op: op,
            last_commit_proof: self.last_commit_proof.clone(),
        })
    }
}

/// Synchronous cache for the compact witness currently safe to serve.
///
/// The cache is intentionally tiny: it only hides the lock used to read and replace the witness.
/// Higher-level persistence and serving logic stays explicit at call sites.
pub(crate) struct Cache<F: Family, D: Digest> {
    witness: RwLock<Witness<F, D>>,
}

impl<F: Family, D: Digest> Cache<F, D> {
    /// Create a cache from the witness loaded or bootstrapped during db initialization.
    pub(crate) const fn new(witness: Witness<F, D>) -> Self {
        Self {
            witness: RwLock::new(witness),
        }
    }

    /// Read the cached witness without exposing the underlying lock to db code.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&Witness<F, D>) -> R) -> R {
        f(&self.witness.read())
    }

    /// Replace the cached witness after the matching compact Merkle state is persisted or loaded.
    pub(crate) fn replace(&self, witness: Witness<F, D>) {
        *self.witness.write() = witness;
    }

    /// Mutate the cache in tests that intentionally corrupt witness state.
    #[cfg(test)]
    pub(crate) fn mutate(&self, f: impl FnOnce(&mut Witness<F, D>)) {
        f(&mut self.witness.write());
    }
}

/// Write the witness portion of `witness` into the given ping-pong slot's db metadata.
///
/// The compact Merkle layer persists the frontier itself. This helper persists the db-owned
/// witness bytes that must move in lockstep with that frontier.
pub(crate) fn write_witness_metadata<E, F, D>(
    metadata: &mut Metadata<E, U64, Vec<u8>>,
    slot: u8,
    witness: &Witness<F, D>,
) where
    E: Context,
    F: Family,
    D: Digest,
{
    metadata.put(
        last_commit_op_key(slot),
        witness.last_commit_op_bytes.clone(),
    );
    metadata.put(
        last_commit_proof_key(slot),
        witness.last_commit_proof.encode().to_vec(),
    );
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

/// Build a witness cache from compact state that was already authenticated by the caller.
#[allow(clippy::type_complexity)]
pub(crate) fn witness_from_authenticated_state<F, E, D, S>(
    merkle: &compact::Merkle<F, E, D, S>,
    inactivity_floor_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
    last_commit_proof: Proof<F, D>,
    pinned_nodes: Vec<D>,
) -> Result<(Location<F>, Witness<F, D>), Error<F>>
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
    let witness = Witness {
        root: merkle.root(),
        leaf_count,
        pinned_nodes,
        last_commit_op_bytes,
        last_commit_proof,
    };
    Ok((last_commit_loc, witness))
}

/// Rebuild the in-memory witness cache from the active slot's persisted witness.
///
/// This is the authoritative recovery path after reopen and rewind. It:
///
/// 1. reads the active slot's commit bytes and proof bytes,
/// 2. decodes the proof,
/// 3. re-verifies that proof against the Merkle currently loaded in memory,
/// 4. reconstructs the frontier pins for serving, and
/// 5. decodes the typed last commit operation needed by the caller's db state.
///
/// Any missing metadata, decode failure, or proof/root mismatch is treated as
/// [`Error::DataCorrupted`], because the persisted frontier and witness no longer describe the same
/// committed state.
pub(crate) async fn load_active_witness<F, E, H, S, C, Op, LastCommitFloor>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    commit_codec_config: &C,
    last_commit_floor: LastCommitFloor,
) -> Result<(Witness<F, H::Digest>, Op), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
    Op: Read<Cfg = C>,
    LastCommitFloor: FnOnce(&Op) -> Option<Location<F>>,
{
    let slot = merkle.active_slot();
    let last_commit_op_bytes = merkle
        .read_metadata_key(&last_commit_op_key(slot))
        .await
        .ok_or(Error::DataCorrupted("missing compact witness"))?;
    let last_commit_proof_bytes = merkle
        .read_metadata_key(&last_commit_proof_key(slot))
        .await
        .ok_or(Error::DataCorrupted("missing compact witness"))?;
    // Every encoded digest is at least `D::SIZE` bytes on the wire, so `proof_bytes.len() /
    // D::SIZE` is a hard upper bound on the digest count. Using this as the decode cap prevents a
    // malformed length prefix from forcing a large preallocation.
    let max_digests = last_commit_proof_bytes.len() / H::Digest::SIZE;
    let last_commit_proof =
        Proof::<F, H::Digest>::decode_cfg(last_commit_proof_bytes.as_ref(), &max_digests)
            .map_err(|_| Error::DataCorrupted("invalid compact witness"))?;
    let root = merkle.root();
    let leaf_count = last_commit_proof.leaves;
    if leaf_count == 0 {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }
    let last_commit_loc = Location::new(*leaf_count - 1);
    let hasher = StandardHasher::<H>::new();
    if !last_commit_proof.verify_element_inclusion(
        &hasher,
        last_commit_op_bytes.as_slice(),
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
    let last_commit_op = Op::decode_cfg(last_commit_op_bytes.as_ref(), commit_codec_config)
        .map_err(|_| Error::DataCorrupted("invalid commit operation"))?;
    let inactivity_floor_loc = last_commit_floor(&last_commit_op)
        .ok_or(Error::DataCorrupted("last operation was not a commit"))?;
    validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
    let witness = Witness {
        root,
        leaf_count,
        pinned_nodes,
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
    let hasher = StandardHasher::<H>::new();
    let batch = {
        let batch = merkle.new_batch().add(&hasher, &last_commit_op_bytes);
        merkle.with_mem(|mem| batch.merkleize(mem, &hasher))
    };
    let last_commit_proof = batch.proof(&hasher, Location::new(0))?;
    merkle.apply_batch(&batch)?;
    merkle
        .sync_with_witness(
            |_| {
                Ok(Witness {
                    root: batch.root(),
                    leaf_count: Location::new(1),
                    pinned_nodes: Vec::new(),
                    last_commit_op_bytes,
                    last_commit_proof,
                })
            },
            |metadata, slot, witness| {
                write_witness_metadata(metadata, slot, &witness);
                Ok(())
            },
        )
        .await?;
    Ok(())
}

/// Persist the current compact witness for a compact db.
///
/// If the cached witness already matches the Merkle root and leaf count being synced, it is copied
/// into the Merkle slot being activated. Otherwise, a new witness is built from the unpruned Merkle
/// before sync prunes it. The cache check runs inside `sync_with_witness` so concurrent syncs
/// observe the latest witness cache after each persisted slot flip.
pub(crate) async fn persist_witness<F, E, H, S>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    cache: &Cache<F, H::Digest>,
    last_commit_loc: Location<F>,
    last_commit_op_bytes: Vec<u8>,
) -> Result<(), Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    let hasher = StandardHasher::<H>::new();
    merkle
        .sync_with_witness(
            |mem| {
                let mem_root = *mem.root();
                let mem_leaves = mem.leaves();
                if let Some(cached) = cache.with(|witness| {
                    (witness.root == mem_root && witness.leaf_count == mem_leaves)
                        .then(|| witness.clone())
                }) {
                    return Ok(cached);
                }
                let pinned_nodes = F::nodes_to_pin(mem_leaves)
                    .map(|pos| *mem.get_node_unchecked(pos))
                    .collect::<Vec<_>>();
                let last_commit_proof = mem.proof(&hasher, last_commit_loc)?;
                Ok(Witness {
                    root: mem_root,
                    leaf_count: mem_leaves,
                    pinned_nodes,
                    last_commit_op_bytes,
                    last_commit_proof,
                })
            },
            |metadata, slot, witness| {
                write_witness_metadata(metadata, slot, &witness);
                cache.replace(witness);
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
            |metadata, slot, witness| {
                write_witness_metadata(metadata, slot, &witness);
                Ok(())
            },
        )
        .await
        .map(|_| ())
        .map_err(Into::into)
}
