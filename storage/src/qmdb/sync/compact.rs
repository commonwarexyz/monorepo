//! Compact sync for compact-storage qmdbs.
//!
//! Compact sync is ordinary [`crate::qmdb::sync::sync`] over a one-operation range. To reach
//! [`Target`] `{ root, leaf_count: N }`, the client syncs the range `[N - 1, N)`. The engine's
//! boundary request fetches the final commit operation, proven at `N`, plus the pins one
//! operation below it, and verifies all of it against `root` before construction. A full
//! database answers that request from its operation log like any other request. A compact
//! database answers from its witness, refusing requests outside the single state it retains.
//!
//! # What compact dbs store
//!
//! A compact db's only persistent state is its witness journal (`qmdb::compact::witness`),
//! whose entries each snapshot one committed state as the commit operation, the committed leaf
//! count, and the pins one operation below it. The in-memory compact Merkle
//! ([`crate::merkle::compact`]) is rebuilt from the journal tip on reopen. Without the witness,
//! a compact db could recover its root and continue appending, but it could not serve compact
//! sync to another node.
//!
//! # When compact state changes
//!
//! The servable compact state advances only on durable persistence. A db-local commit appends
//! one witness entry during `sync`, and `rewind` restores the witness from the target journal
//! entry. Unsynced in-memory mutations are therefore intentionally not servable. `target()`
//! and served responses lag behind `apply_batch()` until the db's next sync.

use crate::merkle::{Family, Location};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::Digest;
use commonware_runtime::{Buf, BufMut};

/// Compact-sync target for a compact-storage database.
///
/// Compact sync authenticates only the final committed root and total leaf count. There is no
/// lower replay bound here because the replayed range is always the single final commit.
#[derive(Debug)]
pub struct Target<F: Family, D: Digest> {
    /// Authenticated root of the committed compact state.
    pub root: D,
    /// Total committed operations/leaves in that state.
    pub leaf_count: Location<F>,
}

impl<F: Family, D: Digest> Target<F, D> {
    /// Create a compact-sync target.
    pub const fn new(root: D, leaf_count: Location<F>) -> Self {
        Self { root, leaf_count }
    }
}

impl<F: Family, D: Digest> Clone for Target<F, D> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            leaf_count: self.leaf_count,
        }
    }
}

impl<F: Family, D: Digest> PartialEq for Target<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.leaf_count == other.leaf_count
    }
}

impl<F: Family, D: Digest> Eq for Target<F, D> {}

impl<F: Family, D: Digest> Write for Target<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.leaf_count.write(buf);
    }
}

impl<F: Family, D: Digest> EncodeSize for Target<F, D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.leaf_count.encode_size()
    }
}

impl<F: Family, D: Digest> Read for Target<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let leaf_count = Location::<F>::read(buf)?;
        if !leaf_count.is_valid() || leaf_count == 0 {
            return Err(CodecError::Invalid(
                "storage::qmdb::sync::compact::Target",
                "leaf_count must be in 1..=MAX_LEAVES",
            ));
        }
        Ok(Self { root, leaf_count })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for Target<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let root = u.arbitrary()?;
        let leaf_count = Location::new(u.int_in_range(1..=*F::MAX_LEAVES)?);
        Ok(Self { root, leaf_count })
    }
}

#[cfg(test)]
mod tests {
    use super::Target;
    use crate::merkle::mmr;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{Hasher as _, sha256::Digest};

    #[test]
    fn test_target_decode_rejects_zero_leaf_count() {
        let unused_root = commonware_cryptography::Sha256::hash(&[b"unused"]);
        let encoded = Target::<mmr::Family, Digest> {
            root: unused_root,
            leaf_count: crate::merkle::Location::new(0),
        }
        .encode();

        assert!(Target::<mmr::Family, Digest>::decode(encoded).is_err());
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use crate::merkle::{mmb, mmr};
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::sha256::Digest as Sha256Digest;

    commonware_conformance::conformance_tests! {
        CodecConformance<Target<mmr::Family, Sha256Digest>>,
        CodecConformance<Target<mmb::Family, Sha256Digest>>,
    }
}
