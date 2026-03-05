//! Decorator for a cryptographic hasher that implements the MMR-specific hashing logic.

use super::{Location, Mmr, Position};
use crate::merkle;
use commonware_cryptography::Hasher as CHasher;

/// A trait for computing the various digests of an MMR.
///
/// This is a blanket alias for [`merkle::hasher::Hasher<Mmr>`] so that existing code can continue
/// to write `H: Hasher<Digest = D>` without specifying the family marker.
pub trait Hasher: merkle::hasher::Hasher<Mmr> {}
impl<T: merkle::hasher::Hasher<Mmr>> Hasher for T {}

/// The standard hasher to use with an MMR. Re-exports the shared [`merkle::hasher::Standard`]
/// with the MMR-specific [`root`](merkle::hasher::Hasher::root) implementation.
pub type Standard<H> = merkle::hasher::Standard<H>;

impl<H: CHasher> merkle::hasher::Hasher<Mmr> for Standard<H> {
    type Digest = H::Digest;
    type Inner = H;

    fn inner(&mut self) -> &mut H {
        &mut self.hasher
    }

    fn fork(&self) -> impl merkle::hasher::Hasher<Mmr, Digest = H::Digest> {
        Self::new()
    }

    fn root<'a>(
        &mut self,
        leaves: Location,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        let inner = self.inner();
        inner.update(&leaves.to_be_bytes());
        for digest in peak_digests {
            inner.update(digest.as_ref());
        }
        inner.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{mem::Mmr, Location};
    use alloc::vec::Vec;
    use commonware_cryptography::{Hasher as CHasher, Sha256};

    #[test]
    fn test_leaf_digest_sha256() {
        test_leaf_digest::<Sha256>();
    }

    #[test]
    fn test_node_digest_sha256() {
        test_node_digest::<Sha256>();
    }

    #[test]
    fn test_root_sha256() {
        test_root::<Sha256>();
    }

    fn test_digest<H: CHasher>(value: u8) -> H::Digest {
        let mut hasher = H::new();
        hasher.update(&[value]);
        hasher.finalize()
    }

    fn test_leaf_digest<H: CHasher>() {
        let mut mmr_hasher: Standard<H> = Standard::new();
        // input hashes to use
        let digest1 = test_digest::<H>(1);
        let digest2 = test_digest::<H>(2);

        let out = mmr_hasher.leaf_digest(Position::new(0), &digest1);
        assert_ne!(out, test_digest::<H>(0), "hash should be non-zero");

        let mut out2 = mmr_hasher.leaf_digest(Position::new(0), &digest1);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.leaf_digest(Position::new(1), &digest1);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.leaf_digest(Position::new(0), &digest2);
        assert_ne!(out, out2, "hash should change with different input digest");
    }

    fn test_node_digest<H: CHasher>() {
        let mut mmr_hasher: Standard<H> = Standard::new();
        // input hashes to use

        let d1 = test_digest::<H>(1);
        let d2 = test_digest::<H>(2);
        let d3 = test_digest::<H>(3);

        let out = mmr_hasher.node_digest(Position::new(0), &d1, &d2);
        assert_ne!(out, test_digest::<H>(0), "hash should be non-zero");

        let mut out2 = mmr_hasher.node_digest(Position::new(0), &d1, &d2);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.node_digest(Position::new(1), &d1, &d2);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.node_digest(Position::new(0), &d3, &d2);
        assert_ne!(
            out, out2,
            "hash should change with different first input hash"
        );

        out2 = mmr_hasher.node_digest(Position::new(0), &d1, &d3);
        assert_ne!(
            out, out2,
            "hash should change with different second input hash"
        );

        out2 = mmr_hasher.node_digest(Position::new(0), &d2, &d1);
        assert_ne!(
            out, out2,
            "hash should change when swapping order of inputs"
        );
    }

    fn test_root<H: CHasher>() {
        let mut mmr_hasher: Standard<H> = Standard::new();
        // input digests to use
        let d1 = test_digest::<H>(1);
        let d2 = test_digest::<H>(2);
        let d3 = test_digest::<H>(3);
        let d4 = test_digest::<H>(4);

        let empty_vec: Vec<H::Digest> = Vec::new();
        let empty_out = mmr_hasher.root(Location::new(0), empty_vec.iter());
        assert_ne!(
            empty_out,
            test_digest::<H>(0),
            "root of empty MMR should be non-zero"
        );
        // Empty MMR root is the hash of size 0 bytes, not the empty hash
        assert_eq!(empty_out, Mmr::empty_mmr_root(mmr_hasher.inner()));

        let digests = [d1, d2, d3, d4];
        let out = mmr_hasher.root(Location::new(10), digests.iter());
        assert_ne!(out, test_digest::<H>(0), "root should be non-zero");
        assert_ne!(out, empty_out, "root should differ from empty MMR");

        let mut out2 = mmr_hasher.root(Location::new(10), digests.iter());
        assert_eq!(out, out2, "root should be computed consistently");

        out2 = mmr_hasher.root(Location::new(11), digests.iter());
        assert_ne!(out, out2, "root should change with different position");

        let digests = [d1, d2, d4, d3];
        out2 = mmr_hasher.root(Location::new(10), digests.iter());
        assert_ne!(out, out2, "root should change with different digest order");

        let digests = [d1, d2, d3];
        out2 = mmr_hasher.root(Location::new(10), digests.iter());
        assert_ne!(
            out, out2,
            "root should change with different number of hashes"
        );
    }
}
