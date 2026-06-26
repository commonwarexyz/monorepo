//! Shared hasher trait and standard implementation for Merkle-family data structures.

use crate::merkle::{Bagging, Error, Family, Location, Position};
use alloc::vec::Vec;
use commonware_codec::{Encode, EncodeRef};
use commonware_cryptography::{Digest, Hasher as CHasher};

/// A trait for computing the various digests of a Merkle-family structure.
///
/// The type parameter `F` determines which Merkle family (MMR, MMB, etc.) this hasher targets, and
/// consequently which `Position` and `Location` types appear in method signatures. Default
/// implementations are provided for all methods except `hash()`.
pub trait Hasher<F: Family>: Clone + Send + Sync {
    type Digest: Digest;

    /// Hash a codec value into a single digest.
    ///
    /// The value is encoded with [`Encode`] and those exact bytes are hashed.
    fn hash<E: Encode>(&mut self, value: E) -> Self::Digest;

    /// The bagging policy applied when this hasher folds peaks into a root. Only affects root peak
    /// aggregation; `hash`, `leaf_digest`, and `node_digest` are unaffected.
    fn root_bagging(&self) -> Bagging;

    /// Computes the digest for a node given its position and the digests of its children.
    fn node_digest(
        &mut self,
        pos: Position<F>,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        self.hash((pos, left, right))
    }

    /// Computes the digest for a leaf given its position and the element it represents.
    fn leaf_digest<E: Encode>(&mut self, pos: Position<F>, element: E) -> Self::Digest {
        self.hash((pos, element))
    }

    /// Computes the digest for a leaf by borrowing the element it represents.
    fn leaf_digest_ref<E: Encode + ?Sized>(
        &mut self,
        pos: Position<F>,
        element: &E,
    ) -> Self::Digest {
        self.hash((pos, EncodeRef::new(element)))
    }

    /// Compute the digest of a codec value.
    fn digest<E: Encode>(&mut self, value: E) -> Self::Digest {
        self.hash(value)
    }

    /// Folds a peak digest into a running accumulator: `Hash(acc || peak)`.
    fn fold(&mut self, acc: &Self::Digest, peak: &Self::Digest) -> Self::Digest {
        self.hash((acc, peak))
    }

    /// Computes a root using `inactive_peaks` and the bagging policy carried by `self`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInactivePeaks`] if `inactive_peaks` exceeds the number of
    /// provided peak digests.
    fn root<'a, I>(
        &mut self,
        leaves: Location<F>,
        inactive_peaks: usize,
        peak_digests: I,
    ) -> Result<Self::Digest, Error<F>>
    where
        I: IntoIterator<Item = &'a Self::Digest>,
        I::IntoIter: ExactSizeIterator,
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
    fn root_with_folded_peaks<'a>(
        &mut self,
        leaves: Location<F>,
        inactive_peaks_to_fold: usize,
        committed_inactive_peaks: usize,
        peak_digests: impl IntoIterator<Item = &'a Self::Digest>,
    ) -> Option<Self::Digest> {
        let mut peak_digests = peak_digests.into_iter();
        let Some(first) = peak_digests.next() else {
            return (inactive_peaks_to_fold == 0 && committed_inactive_peaks == 0)
                .then(|| self.digest(leaves));
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
            Bagging::BackwardFold => {
                let (lower, upper) = peak_digests.size_hint();
                let mut active_peaks = Vec::with_capacity(1 + upper.unwrap_or(lower));
                active_peaks.push(acc);
                active_peaks.extend(peak_digests.copied());

                let mut acc = *active_peaks.last().unwrap();
                for peak in active_peaks.iter().rev().skip(1) {
                    acc = self.fold(peak, &acc);
                }
                acc
            }
        };

        if committed_inactive_peaks == 0 {
            Some(self.hash((leaves, folded_peaks)))
        } else {
            Some(self.hash((leaves, committed_inactive_peaks, folded_peaks)))
        }
    }
}

/// The standard hasher for Merkle-family structures. Leverages no external data.
///
/// A single `Standard<H>` implements `Hasher<F>` for every Merkle family `F`, so
/// one instance can be used with MMR, MMB, or any future family.
///
/// The `bagging` field selects how peaks are folded into the root.
#[derive(Clone)]
pub struct Standard<H: CHasher> {
    hasher: H,
    bagging: Bagging,
}

impl<H: CHasher> Standard<H> {
    /// Creates a new [Standard] hasher with the given bagging policy.
    pub fn new(bagging: Bagging) -> Self {
        Self {
            hasher: H::new(),
            bagging,
        }
    }

    /// Return the bagging policy used when folding peaks into a root.
    pub const fn root_bagging(&self) -> Bagging {
        self.bagging
    }

    /// Hash a codec value into a single digest.
    pub fn hash<E: Encode>(&mut self, value: E) -> H::Digest {
        self.hasher.hash_codec(value)
    }

    /// Compute the digest of a codec value.
    pub fn digest<E: Encode>(&mut self, value: E) -> H::Digest {
        self.hash(value)
    }
}

impl<F: Family, H: CHasher> Hasher<F> for Standard<H> {
    type Digest = H::Digest;

    fn hash<E: Encode>(&mut self, value: E) -> H::Digest {
        Self::hash(self, value)
    }

    fn root_bagging(&self) -> Bagging {
        Self::root_bagging(self)
    }

    #[inline]
    fn node_digest(
        &mut self,
        pos: Position<F>,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        self.hasher.hash_codec((pos, left, right))
    }

    #[inline]
    fn leaf_digest<E: Encode>(&mut self, pos: Position<F>, element: E) -> Self::Digest {
        self.hasher.hash_codec((pos, element))
    }

    #[inline]
    fn leaf_digest_ref<E: Encode + ?Sized>(
        &mut self,
        pos: Position<F>,
        element: &E,
    ) -> Self::Digest {
        self.hasher.hash_codec((pos, EncodeRef::new(element)))
    }

    #[inline]
    fn fold(&mut self, acc: &Self::Digest, peak: &Self::Digest) -> Self::Digest {
        self.hasher.hash_codec((acc, peak))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{
        mmr::{Location, Position, StandardHasher as Standard},
        Bagging::{BackwardFold, ForwardFold},
    };
    use alloc::vec::Vec;
    use commonware_cryptography::{sha256, Hasher as CHasher, Sha256};

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
    fn test_invalid_inactive_prefix_returns_err() {
        let mut mmr_hasher: Standard<Sha256> = Standard::new(BackwardFold);
        let d1 = test_digest::<Sha256>(1);
        let d2 = test_digest::<Sha256>(2);
        let digests = [d1, d2];

        assert!(matches!(
            <Standard<Sha256> as Hasher<crate::merkle::mmr::Family>>::root(
                &mut mmr_hasher,
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
                &mut mmr_hasher,
                Location::new(2),
                3,
                3,
                digests.iter()
            )
            .is_none()
        );
        assert!(matches!(
            <Standard<Sha256> as Hasher<crate::merkle::mmr::Family>>::root(
                &mut mmr_hasher,
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
        H::hash(&[value])
    }

    fn test_leaf_digest<H: CHasher>() {
        let mut mmr_hasher: Standard<H> = Standard::new(ForwardFold);
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

        // A leaf element far longer than the fixed-hash scratch must stream to the correct digest
        // rather than overrun the scratch.
        let big = [0xABu8; 200];
        let pos = Position::new(2);
        let out_big = mmr_hasher.leaf_digest(pos, &big);
        let expected_big = mmr_hasher.hash((pos, &big));
        assert_eq!(
            out_big, expected_big,
            "large leaf elements must stream to the same digest"
        );
    }

    fn test_node_digest<H: CHasher>() {
        let mut mmr_hasher: Standard<H> = Standard::new(ForwardFold);

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
        let mut mmr_hasher: Standard<H> = Standard::new(ForwardFold);
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
