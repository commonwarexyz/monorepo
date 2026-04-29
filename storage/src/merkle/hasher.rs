//! Shared hasher trait and standard implementation for Merkle-family data structures.

use crate::merkle::{Bagging, Error, Family, Location, Position, RootSpec};
use alloc::vec::Vec;
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

    /// Computes a root according to the supplied [`RootSpec`].
    fn root<'a, I>(
        &self,
        leaves: Location<F>,
        spec: RootSpec,
        peak_digests: I,
    ) -> Result<Self::Digest, Error<F>>
    where
        I: IntoIterator<Item = &'a Self::Digest>,
        I::IntoIter: ExactSizeIterator,
    {
        self.root_with_inactive_prefix(leaves, spec.inactive_peaks, spec.bagging, peak_digests)
    }

    /// Computes a root where the oldest `inactive_peaks` are forward-bagged into a single
    /// accumulator and the remaining peaks are folded with the strategy indicated by `bagging`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInactivePeaks`] if `inactive_peaks` exceeds the number of
    /// provided peak digests.
    fn root_with_inactive_prefix<'a, I>(
        &self,
        leaves: Location<F>,
        inactive_peaks: usize,
        bagging: Bagging,
        peak_digests: I,
    ) -> Result<Self::Digest, Error<F>>
    where
        I: IntoIterator<Item = &'a Self::Digest>,
        I::IntoIter: ExactSizeIterator,
    {
        let iter = peak_digests.into_iter();
        let peaks = iter.len();
        self.root_with_folded_peaks(leaves, inactive_peaks, inactive_peaks, bagging, iter)
            .ok_or(Error::InvalidInactivePeaks {
                requested: inactive_peaks,
                peaks,
            })
    }

    /// Computes a root from a peak list that may already contain a forward-folded prefix
    /// accumulator.
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
        &self,
        leaves: Location<F>,
        inactive_peaks_to_fold: usize,
        committed_inactive_peaks: usize,
        bagging: Bagging,
        peak_digests: impl IntoIterator<Item = &'a Self::Digest>,
    ) -> Option<Self::Digest> {
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

        let folded_peaks = match bagging {
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
            Some(self.hash([(*leaves).to_be_bytes().as_slice(), folded_peaks.as_ref()]))
        } else {
            Some(self.hash([
                (*leaves).to_be_bytes().as_slice(),
                (committed_inactive_peaks as u64).to_be_bytes().as_slice(),
                folded_peaks.as_ref(),
            ]))
        }
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

// This intentionally forwards only `hash`: the default `Hasher` methods are all expressed in terms
// of `hash`. If a future hasher specializes other methods, forward those here as well.
impl<F: Family, T: Hasher<F>> Hasher<F> for &T {
    type Digest = T::Digest;

    fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        (**self).hash(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr::{Location, Position, StandardHasher as Standard};
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
        let mmr_hasher: Standard<Sha256> = Standard::new();
        let d1 = test_digest::<Sha256>(1);
        let d2 = test_digest::<Sha256>(2);
        let digests = [d1, d2];

        assert!(matches!(
            mmr_hasher.root_with_inactive_prefix(
                Location::new(2),
                3,
                Bagging::BackwardFold,
                digests.iter()
            ),
            Err(crate::merkle::Error::InvalidInactivePeaks {
                requested: 3,
                peaks: 2
            })
        ));
        assert!(mmr_hasher
            .root_with_folded_peaks(
                Location::new(2),
                3,
                3,
                Bagging::BackwardFold,
                digests.iter()
            )
            .is_none());
        assert!(matches!(
            mmr_hasher.root_with_inactive_prefix(
                Location::new(0),
                1,
                Bagging::BackwardFold,
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
        let empty_out = mmr_hasher
            .root(Location::new(0), RootSpec::FULL_FORWARD, empty_vec.iter())
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
                .root(Location::new(0), RootSpec::FULL_FORWARD, empty_vec.iter())
                .expect("zero inactive peaks is always valid")
        );

        let digests = [d1, d2, d3, d4];
        let out = mmr_hasher
            .root(Location::new(10), RootSpec::FULL_FORWARD, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_ne!(out, test_digest::<H>(0), "root should be non-zero");
        assert_ne!(out, empty_out, "root should differ from empty MMR");

        let mut out2 = mmr_hasher
            .root(Location::new(10), RootSpec::FULL_FORWARD, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_eq!(out, out2, "root should be computed consistently");

        out2 = mmr_hasher
            .root(Location::new(11), RootSpec::FULL_FORWARD, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_ne!(out, out2, "root should change with different position");

        let digests = [d1, d2, d4, d3];
        out2 = mmr_hasher
            .root(Location::new(10), RootSpec::FULL_FORWARD, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_ne!(out, out2, "root should change with different digest order");

        let digests = [d1, d2, d3];
        out2 = mmr_hasher
            .root(Location::new(10), RootSpec::FULL_FORWARD, digests.iter())
            .expect("zero inactive peaks is always valid");
        assert_ne!(
            out, out2,
            "root should change with different number of hashes"
        );
    }
}
