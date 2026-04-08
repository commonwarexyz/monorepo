//! Shared hasher trait and standard implementation for Merkle-family data structures.

use crate::merkle::{Family, Location, Position};
use commonware_cryptography::{Digest, Hasher as CHasher};
use core::marker::PhantomData;

/// A trait for computing the various digests of a Merkle-family structure.
///
/// The type parameter `F` determines which Merkle family (MMR, MMB, etc.) this hasher targets, and
/// consequently which `Position` and `Location` types appear in method signatures. Default
/// implementations are provided for all methods except `hash()`.
pub trait Hasher<F: Family>: Clone + Send + Sync {
    type Digest: Digest;

    /// Hash an arbitrary sequence of byte slices into a single digest.
    ///
    /// The parts are concatenated before hashing (i.e. there is no domain separation between
    /// parts).
    fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest;

    /// Computes the digest for a node given its position and the digests of its children.
    fn node_digest(
        &self,
        pos: Position<F>,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        self.hash([
            (*pos).to_be_bytes().as_slice(),
            left.as_ref(),
            right.as_ref(),
        ])
    }

    /// Computes the digest for a leaf given its position and the element it represents.
    fn leaf_digest(&self, pos: Position<F>, element: &[u8]) -> Self::Digest {
        self.hash([(*pos).to_be_bytes().as_slice(), element])
    }

    /// Compute the digest of a byte slice.
    fn digest(&self, data: &[u8]) -> Self::Digest {
        self.hash(core::iter::once(data))
    }

    /// Folds a peak digest into a running accumulator: `Hash(acc || peak)`.
    fn fold(&self, acc: &Self::Digest, peak: &Self::Digest) -> Self::Digest {
        self.hash([acc.as_ref(), peak.as_ref()])
    }

    /// Computes the root for the structure given its leaf count and peak digests in canonical order.
    ///
    /// The root digest is computed as `Hash(leaves || fold(peak_digests))`, where `fold` is
    /// defined as `fold(acc, peak) = Hash(acc || peak)`. The `peak_digests` are assumed to be
    /// in canonical order.
    fn root<'a>(
        &self,
        leaves: Location<F>,
        peak_digests: impl IntoIterator<Item = &'a Self::Digest>,
    ) -> Self::Digest {
        let mut iter = peak_digests.into_iter();
        let Some(first) = iter.next() else {
            return self.digest(&(*leaves).to_be_bytes());
        };
        let acc = iter.fold(*first, |acc, digest| self.fold(&acc, digest));

        self.hash([(*leaves).to_be_bytes().as_slice(), acc.as_ref()])
    }
}

/// The standard hasher for Merkle-family structures. Leverages no external data.
///
/// A single `Standard<H>` implements `Hasher<F>` for every Merkle family `F`, so
/// one instance can be used with MMR, MMB, or any future family.
#[derive(Clone)]
pub struct Standard<H: CHasher> {
    _hasher: PhantomData<H>,
}

impl<H: CHasher> Standard<H> {
    /// Creates a new [Standard] hasher.
    pub const fn new() -> Self {
        Self {
            _hasher: PhantomData,
        }
    }

    /// Hash an arbitrary sequence of byte slices into a single digest.
    pub fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> H::Digest {
        let mut h = H::new();
        for part in parts {
            h.update(part);
        }
        h.finalize()
    }

    /// Compute the digest of a byte slice.
    pub fn digest(&self, data: &[u8]) -> H::Digest {
        self.hash(core::iter::once(data))
    }
}

impl<H: CHasher> Default for Standard<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Family, H: CHasher> Hasher<F> for Standard<H> {
    type Digest = H::Digest;

    fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> H::Digest {
        Self::hash(self, parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr::{Location, Position, StandardHasher as Standard};
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
        H::hash(&[value])
    }

    fn test_leaf_digest<H: CHasher>() {
        let mmr_hasher: Standard<H> = Standard::new();
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
        let mmr_hasher: Standard<H> = Standard::new();

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
        let mmr_hasher: Standard<H> = Standard::new();
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
        // Empty root is deterministic.
        assert_eq!(
            empty_out,
            mmr_hasher.root(Location::new(0), empty_vec.iter())
        );

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
