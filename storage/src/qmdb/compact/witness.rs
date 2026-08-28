//! The persisted witness of a compact-db state and its verification.
//!
//! A [`Witness`] records one applied state: the commit operation, the committed size, and the
//! pinned nodes one operation below it. The commit's inclusion proof is not stored. [`restore`]
//! rebuilds the Merkle by appending the commit operation to the pinned nodes and derives the root
//! and proof from it; a structurally invalid entry fails with [`Error::DataCorrupted`].

use super::operation::Operation;
use crate::{
    journal::contiguous::variable,
    merkle::{Family, Location, MAX_PINNED_NODES, Proof, compact},
    qmdb::{self, Error, sync::CompactTarget},
};
use commonware_codec::{EncodeSize, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;

/// An applied state persisted by the witness journal.
#[derive(Clone)]
pub(crate) struct Witness<F: Family, D: Digest, O: Operation<F>> {
    /// The last commit operation, at `size - 1`.
    pub(crate) commit: O,
    /// The committed database size.
    pub(crate) size: Location<F>,
    /// Pinned nodes at the commit operation, in the order returned by
    /// [`Family::nodes_to_pin`].
    pub(crate) pinned_nodes: Vec<D>,
}

impl<F: Family, D: Digest, O: Operation<F>> EncodeSize for Witness<F, D, O> {
    fn encode_size(&self) -> usize {
        self.commit.encode_size() + self.size.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl<F: Family, D: Digest, O: Operation<F>> Write for Witness<F, D, O> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commit.write(buf);
        self.size.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl<F: Family, D: Digest, O: Operation<F>> Read for Witness<F, D, O> {
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
    O: Operation<F> + for<'a> arbitrary::Arbitrary<'a>,
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
pub(super) struct VerifiedWitness<F: Family, D: Digest, O: Operation<F>> {
    pub(super) witness: Witness<F, D, O>,
    /// Inactivity floor declared by the commit.
    pub(super) inactivity_floor_loc: Location<F>,
    /// Root committed by `witness`.
    pub(super) root: D,
    /// Inclusion proof for the commit at `size - 1` against `root`, derived from the
    /// witness when it was built or loaded.
    pub(super) proof: Proof<F, D>,
}

impl<F: Family, D: Digest, O: Operation<F>> VerifiedWitness<F, D, O> {
    /// The committed size, which also identifies the last commit's location.
    pub(super) const fn size(&self) -> Location<F> {
        self.witness.size
    }

    /// The metadata carried by the commit.
    pub(super) fn metadata(&self) -> Option<&O::Metadata> {
        self.witness.commit.metadata()
    }

    /// The compact-sync target (root and size) this witness can serve.
    pub(super) const fn target(&self) -> CompactTarget<F, D> {
        CompactTarget {
            root: self.root,
            size: self.size(),
        }
    }
}

/// The contiguous variable journal of a compact db's witnesses.
pub(crate) type Journal<E, F, D, O> = variable::Journal<E, Witness<F, D, O>>;

/// A Merkle materialized from a witness, with the witness verified against it.
pub(super) struct Rebuilt<F: Family, D: Digest, O: Operation<F>, S: Strategy> {
    pub(super) merkle: compact::Merkle<F, D, S>,
    pub(super) tip: VerifiedWitness<F, D, O>,
}

/// Build a witness for `commit`, the last operation in `merkle`.
///
/// The tip operation's inclusion proof is only computable before the Merkle is pruned to its
/// frontier.
pub(super) fn build_witness<F, O, H, S>(
    merkle: &compact::Merkle<F, H::Digest, S>,
    commit: O,
    inactivity_floor_loc: Location<F>,
) -> Result<VerifiedWitness<F, H::Digest, O>, Error<F>>
where
    F: Family,
    O: Operation<F>,
    H: Hasher,
    S: Strategy,
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

/// Validate that a commit floor does not point past the commit it authenticates.
///
/// A higher floor would reference operations that do not exist yet, which indicates disk
/// corruption in a persisted witness or a bad import.
pub(super) fn validate_inactivity_floor<F: Family>(
    inactivity_floor_loc: Location<F>,
    last_commit_loc: Location<F>,
) -> Result<(), Error<F>> {
    if inactivity_floor_loc > last_commit_loc {
        return Err(Error::DataCorrupted("invalid compact witness"));
    }
    Ok(())
}

/// Materialize the Merkle `witness` describes and derive its root and commit proof.
///
/// The Merkle is built from the pinned nodes one operation below the commit plus the commit
/// itself, then pruned back to its frontier. Merkle errors propagate unchanged.
pub(super) fn restore<F, O, H, S>(
    strategy: S,
    witness: Witness<F, H::Digest, O>,
    inactivity_floor_loc: Location<F>,
) -> Result<Rebuilt<F, H::Digest, O, S>, Error<F>>
where
    F: Family,
    O: Operation<F>,
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
    let tip = build_witness::<F, O, H, S>(&merkle, commit, inactivity_floor_loc)?;
    merkle.prune_to_frontier();
    Ok(Rebuilt { merkle, tip })
}

/// Validate a journaled witness, then restore it. Any failure is [`Error::DataCorrupted`]: the
/// entry came from this db's own journal.
pub(super) fn rebuild<F, O, H, S>(
    strategy: S,
    witness: Witness<F, H::Digest, O>,
) -> Result<Rebuilt<F, H::Digest, O, S>, Error<F>>
where
    F: Family,
    O: Operation<F>,
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
    use crate::{Context, journal::contiguous::Contiguous};

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
        O: Operation<F>,
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
        O: Operation<F>,
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
        O: Operation<F>,
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
        O: Operation<F>,
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
