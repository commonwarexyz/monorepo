//! Shared hasher trait and standard implementation for Merkle-family data structures.

use crate::merkle::{Bagging, Error, Family, Location, Position};
use alloc::vec::Vec;
use commonware_cryptography::{Digest, Hasher as CHasher};
use core::marker::PhantomData;

/// A trait for computing the various digests of a Merkle-family structure.
///
/// The type parameter `F` determines which Merkle family (MMR, MMB, etc.) this hasher targets, and
/// consequently which `Position` and `Location` types appear in method signatures.
pub trait Hasher<F: Family>: Clone + Send + Sync {
    /// Digest produced by this hasher.
    type Digest: Digest;

    /// Hash a sequence of byte slices into a single digest.
    ///
    /// The parts are concatenated before hashing (i.e. there is no domain separation between
    /// parts).
    fn hash(&self, parts: &[&[u8]]) -> Self::Digest;

    /// The bagging policy applied when this hasher folds peaks into a root. Only affects root peak
    /// aggregation; `hash`, `leaf_digest`, and `node_digest` are unaffected.
    fn root_bagging(&self) -> Bagging;

    /// Computes the digest for a node given its position and the digests of its children.
    fn node_digest(
        &self,
        pos: Position<F>,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        self.hash(&[&(*pos).to_be_bytes(), left, right])
    }

    /// Computes the digests of many nodes, each given as its position and the digests of its
    /// children, so the hasher can hash them together.
    ///
    /// Must be equivalent to one [`node_digest`](Self::node_digest) call per node, in order.
    fn node_digests(
        &self,
        nodes: &[(Position<F>, Self::Digest, Self::Digest)],
    ) -> Vec<Self::Digest>;

    /// Computes the digest for a leaf given its position and the element it represents.
    fn leaf_digest(&self, pos: Position<F>, element: &[u8]) -> Self::Digest {
        self.hash(&[&(*pos).to_be_bytes(), element])
    }

    /// Computes the digests of many leaves, each given as its position and the element it
    /// represents, so the hasher can hash them together.
    ///
    /// Must be equivalent to one [`leaf_digest`](Self::leaf_digest) call per leaf, in order.
    fn leaf_digests(&self, leaves: &[(Position<F>, &[u8])]) -> Vec<Self::Digest>;

    /// Compute the digest of a byte slice.
    fn digest(&self, data: &[u8]) -> Self::Digest {
        self.hash(&[data])
    }

    /// Folds a peak digest into a running accumulator: `Hash(acc || peak)`.
    fn fold(&self, acc: &Self::Digest, peak: &Self::Digest) -> Self::Digest {
        self.hash(&[acc, peak])
    }

    /// Computes a root using `inactive_peaks` and the bagging policy carried by `self`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInactivePeaks`] if `inactive_peaks` exceeds the number of
    /// provided peak digests.
    fn root<'a, I>(
        &self,
        leaves: Location<F>,
        inactive_peaks: usize,
        peak_digests: I,
    ) -> Result<Self::Digest, Error<F>>
    where
        I: IntoIterator<Item = &'a Self::Digest>,
        I::IntoIter: ExactSizeIterator + DoubleEndedIterator,
    {
        let iter = peak_digests.into_iter();
        let peaks = iter.len();
        self.root_with_folded_peaks(leaves, inactive_peaks, inactive_peaks, iter)
            .ok_or(Error::InvalidInactivePeaks {
                requested: inactive_peaks,
                peaks,
            })
    }

    /// Computes a root from a peak list that may already contain a forward-folded prefix
    /// accumulator. The bagging policy is read from `self.root_bagging()`.
    ///
    /// `inactive_peaks_to_fold` is how many leading entries of `peak_digests` to fold before the
    /// root bagging step. `committed_inactive_peaks` is the boundary committed into the root. They
    /// coincide when the caller passes raw peak digests, but diverge when the caller has already
    /// pre-folded part of the inactive prefix: e.g. a proof commits 5 inactive peaks, an outer
    /// transform collapses the first 3 into a leading accumulator, so the hasher gets `to_fold = 5
    /// - 3 + 1 = 3` while `committed = 5`.
    ///
    /// Returns `None` if `inactive_peaks_to_fold` exceeds the number of provided peak digests, or
    /// if a nonzero inactive boundary is requested for an empty tree.
    fn root_with_folded_peaks<'a, I>(
        &self,
        leaves: Location<F>,
        inactive_peaks_to_fold: usize,
        committed_inactive_peaks: usize,
        peak_digests: I,
    ) -> Option<Self::Digest>
    where
        I: IntoIterator<Item = &'a Self::Digest>,
        I::IntoIter: DoubleEndedIterator,
    {
        let mut peak_digests = peak_digests.into_iter();
        let Some(first) = peak_digests.next() else {
            return (inactive_peaks_to_fold == 0 && committed_inactive_peaks == 0)
                .then(|| self.digest(&(*leaves).to_be_bytes()));
        };

        let mut acc = *first;
        for _ in 0..inactive_peaks_to_fold.saturating_sub(1) {
            let peak = peak_digests.next()?;
            acc = self.fold(&acc, peak);
        }

        let folded_peaks = match self.root_bagging() {
            Bagging::ForwardFold => {
                for peak in peak_digests {
                    acc = self.fold(&acc, peak);
                }
                acc
            }
            Bagging::BackwardFold => peak_digests
                .rev()
                .copied()
                .reduce(|bag, peak| self.fold(&peak, &bag))
                .map_or(acc, |bag| self.fold(&acc, &bag)),
        };

        if committed_inactive_peaks == 0 {
            Some(self.hash(&[&(*leaves).to_be_bytes(), &folded_peaks]))
        } else {
            Some(self.hash(&[
                &(*leaves).to_be_bytes(),
                &(committed_inactive_peaks as u64).to_be_bytes(),
                &folded_peaks,
            ]))
        }
    }
}

/// The standard hasher for Merkle-family structures. Leverages no external data.
///
/// A single `Standard<H>` implements `Hasher<F>` for every Merkle family `F`, so
/// one instance can be used with MMR, MMB, or any future family.
///
/// The `bagging` field selects how peaks are folded into the root.
pub struct Standard<H: CHasher> {
    _hasher: PhantomData<H>,
    bagging: Bagging,
}

impl<H: CHasher> Clone for Standard<H> {
    fn clone(&self) -> Self {
        Self {
            _hasher: PhantomData,
            bagging: self.bagging,
        }
    }
}

impl<H: CHasher> Standard<H> {
    /// Creates a new [Standard] hasher with the given bagging policy.
    pub const fn new(bagging: Bagging) -> Self {
        Self {
            _hasher: PhantomData,
            bagging,
        }
    }

    /// Return the bagging policy used when folding peaks into a root.
    pub const fn root_bagging(&self) -> Bagging {
        self.bagging
    }

    /// Hash a sequence of byte slices into a single digest.
    pub fn hash(&self, parts: &[&[u8]]) -> H::Digest {
        H::hash(parts)
    }

    /// Compute the digest of a byte slice.
    pub fn digest(&self, data: &[u8]) -> H::Digest {
        self.hash(&[data])
    }
}

impl<F: Family, H: CHasher> Hasher<F> for Standard<H> {
    type Digest = H::Digest;

    fn hash(&self, parts: &[&[u8]]) -> H::Digest {
        Self::hash(self, parts)
    }

    fn root_bagging(&self) -> Bagging {
        Self::root_bagging(self)
    }

    fn node_digests(
        &self,
        nodes: &[(Position<F>, Self::Digest, Self::Digest)],
    ) -> Vec<Self::Digest> {
        let positions: Vec<[u8; 8]> = nodes
            .iter()
            .map(|(pos, ..)| (**pos).to_be_bytes())
            .collect();
        let messages: Vec<[&[u8]; 3]> = positions
            .iter()
            .zip(nodes)
            .map(|(pos, (_, left, right))| [pos.as_slice(), left.as_ref(), right.as_ref()])
            .collect();
        H::hash_many_parts(&messages)
    }

    fn leaf_digests(&self, leaves: &[(Position<F>, &[u8])]) -> Vec<Self::Digest> {
        let positions: Vec<[u8; 8]> = leaves
            .iter()
            .map(|(pos, _)| (**pos).to_be_bytes())
            .collect();
        let messages: Vec<[&[u8]; 2]> = positions
            .iter()
            .zip(leaves)
            .map(|(pos, (_, element))| [pos.as_slice(), *element])
            .collect();
        H::hash_many_parts(&messages)
    }
}

impl<F: Family, T: Hasher<F>> Hasher<F> for &T {
    type Digest = T::Digest;

    fn hash(&self, parts: &[&[u8]]) -> Self::Digest {
        (**self).hash(parts)
    }

    fn root_bagging(&self) -> Bagging {
        (**self).root_bagging()
    }

    fn node_digest(
        &self,
        pos: Position<F>,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        (**self).node_digest(pos, left, right)
    }

    fn leaf_digest(&self, pos: Position<F>, element: &[u8]) -> Self::Digest {
        (**self).leaf_digest(pos, element)
    }

    fn leaf_digests(&self, leaves: &[(Position<F>, &[u8])]) -> Vec<Self::Digest> {
        (**self).leaf_digests(leaves)
    }

    fn digest(&self, data: &[u8]) -> Self::Digest {
        (**self).digest(data)
    }

    fn fold(&self, acc: &Self::Digest, peak: &Self::Digest) -> Self::Digest {
        (**self).fold(acc, peak)
    }

    fn root<'a, I>(
        &self,
        leaves: Location<F>,
        inactive_peaks: usize,
        peak_digests: I,
    ) -> Result<Self::Digest, Error<F>>
    where
        I: IntoIterator<Item = &'a Self::Digest>,
        I::IntoIter: ExactSizeIterator + DoubleEndedIterator,
    {
        (**self).root(leaves, inactive_peaks, peak_digests)
    }

    fn root_with_folded_peaks<'a, I>(
        &self,
        leaves: Location<F>,
        inactive_peaks_to_fold: usize,
        committed_inactive_peaks: usize,
        peak_digests: I,
    ) -> Option<Self::Digest>
    where
        I: IntoIterator<Item = &'a Self::Digest>,
        I::IntoIter: DoubleEndedIterator,
    {
        (**self).root_with_folded_peaks(
            leaves,
            inactive_peaks_to_fold,
            committed_inactive_peaks,
            peak_digests,
        )
    }

    fn node_digests(
        &self,
        nodes: &[(Position<F>, Self::Digest, Self::Digest)],
    ) -> Vec<Self::Digest> {
        (**self).node_digests(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{
        Bagging::{BackwardFold, ForwardFold},
        mmr::{Location, Position, StandardHasher as Standard},
    };
    use commonware_cryptography::{Blake3, Hasher as CHasher, Sha256, sha256};
    use commonware_utils::test_rng;
    use rand::Rng as _;

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

    #[test]
    fn test_node_digests_sha256() {
        test_node_digests::<Sha256>();
    }

    #[test]
    fn test_node_digests_blake3() {
        test_node_digests::<Blake3>();
    }

    #[test]
    fn test_leaf_digests_sha256() {
        test_leaf_digests::<Sha256>();
    }

    #[test]
    fn test_leaf_digests_blake3() {
        test_leaf_digests::<Blake3>();
    }

    fn test_leaf_digests<H: CHasher>() {
        let hasher: Standard<H> = Standard::new(ForwardFold);
        let mut data = vec![0u8; 4096];
        test_rng().fill_bytes(&mut data);
        for count in [0, 1, 2, 3, 16, 17, 33] {
            // Equal lengths (fixed operations) and varying lengths (variable operations).
            for varying in [false, true] {
                let leaves: Vec<(Position, &[u8])> = (0..count)
                    .map(|i| {
                        let len = if varying { 33 + 7 * i } else { 105 };
                        (Position::new(3 * i as u64), &data[i..i + len])
                    })
                    .collect();
                let expected: Vec<_> = leaves
                    .iter()
                    .map(|(pos, element)| hasher.leaf_digest(*pos, element))
                    .collect();
                assert_eq!(
                    hasher.leaf_digests(&leaves),
                    expected,
                    "count {count} varying {varying}"
                );
            }
        }
    }

    fn test_node_digests<H: CHasher>() {
        let hasher: Standard<H> = Standard::new(ForwardFold);
        for count in [0, 1, 2, 3, 16, 17, 33] {
            let nodes: Vec<_> = (0..count as u64)
                .map(|i| {
                    (
                        Position::new(2 + 3 * i),
                        test_digest::<H>(2 * i as u8),
                        test_digest::<H>(2 * i as u8 + 1),
                    )
                })
                .collect();
            let expected: Vec<_> = nodes
                .iter()
                .map(|(pos, left, right)| hasher.node_digest(*pos, left, right))
                .collect();
            assert_eq!(hasher.node_digests(&nodes), expected, "count {count}");
        }
    }

    #[test]
    fn test_invalid_inactive_prefix_returns_err() {
        let mmr_hasher: Standard<Sha256> = Standard::new(BackwardFold);
        let d1 = test_digest::<Sha256>(1);
        let d2 = test_digest::<Sha256>(2);
        let digests = [d1, d2];

        assert!(matches!(
            <Standard<Sha256> as Hasher<crate::merkle::mmr::Family>>::root(
                &mmr_hasher,
                Location::new(2),
                3,
                digests.iter()
            ),
            Err(crate::merkle::Error::InvalidInactivePeaks {
                requested: 3,
                peaks: 2
            })
        ));
        assert!(
            <Standard<Sha256> as Hasher<crate::merkle::mmr::Family>>::root_with_folded_peaks(
                &mmr_hasher,
                Location::new(2),
                3,
                3,
                digests.iter()
            )
            .is_none()
        );
        assert!(matches!(
            <Standard<Sha256> as Hasher<crate::merkle::mmr::Family>>::root(
                &mmr_hasher,
                Location::new(0),
                1,
                Vec::<sha256::Digest>::new().iter()
            ),
            Err(crate::merkle::Error::InvalidInactivePeaks {
                requested: 1,
                peaks: 0
            })
        ));
    }

    fn test_digest<H: CHasher>(value: u8) -> H::Digest {
        H::hash(&[&[value]])
    }

    fn test_leaf_digest<H: CHasher>() {
        let mmr_hasher: Standard<H> = Standard::new(ForwardFold);
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
        let mmr_hasher: Standard<H> = Standard::new(ForwardFold);

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
        let mmr_hasher: Standard<H> = Standard::new(ForwardFold);
        let d1 = test_digest::<H>(1);
        let d2 = test_digest::<H>(2);
        let d3 = test_digest::<H>(3);
        let d4 = test_digest::<H>(4);

        let empty_vec: Vec<H::Digest> = Vec::new();
        let empty_out = mmr_hasher
            .root(Location::new(0), 0, empty_vec.iter())
            .expect("zero inactive peaks is always valid");
        assert_ne!(
            empty_out,
            test_digest::<H>(0),
            "root of empty MMR should be non-zero"
        );
        // Empty root is deterministic.
        assert_eq!(
            empty_out,
            mmr_hasher
                .root(Location::new(0), 0, empty_vec.iter())
                .expect("zero inactive peaks is always valid")
        );

        let digests = [d1, d2, d3, d4];
        let out = mmr_hasher
            .root(Location::new(10), 0, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_ne!(out, test_digest::<H>(0), "root should be non-zero");
        assert_ne!(out, empty_out, "root should differ from empty MMR");

        let mut out2 = mmr_hasher
            .root(Location::new(10), 0, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_eq!(out, out2, "root should be computed consistently");

        out2 = mmr_hasher
            .root(Location::new(11), 0, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_ne!(out, out2, "root should change with different position");

        let digests = [d1, d2, d4, d3];
        out2 = mmr_hasher
            .root(Location::new(10), 0, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_ne!(out, out2, "root should change with different digest order");

        let digests = [d1, d2, d3];
        out2 = mmr_hasher
            .root(Location::new(10), 0, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_ne!(
            out, out2,
            "root should change with different number of hashes"
        );
    }
}
