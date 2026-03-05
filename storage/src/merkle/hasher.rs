//! Shared hasher trait and standard implementation for Merkle-family data structures.

use super::{Location, MerkleFamily, Position};
use commonware_cryptography::{Digest, Hasher as CHasher};

/// A trait for computing the various digests of a Merkle-family structure.
///
/// The `root()`, `inner()`, and `fork()` methods are family-specific and must be implemented.
/// Default implementations are provided for `leaf_digest()`, `node_digest()`, `fold_peak()`,
/// and `digest()`.
pub trait Hasher<F: MerkleFamily>: Send + Sync {
    type Digest: Digest;
    type Inner: CHasher<Digest = Self::Digest>;

    /// Computes the root for the structure given its leaf count and an iterator over peak digests.
    fn root<'a>(
        &mut self,
        leaves: Location<F>,
        peak_digests: impl Iterator<Item = &'a Self::Digest>,
    ) -> Self::Digest;

    /// Access the inner cryptographic hasher.
    fn inner(&mut self) -> &mut Self::Inner;

    /// Fork the hasher to provide equivalent functionality in another thread. This is different
    /// than [Clone::clone] because the forked hasher need not be a deep copy, and may share
    /// non-mutable state with the hasher from which it was forked.
    fn fork(&self) -> impl Hasher<F, Digest = Self::Digest>;

    /// Computes the digest for a leaf given its position and the element it represents.
    fn leaf_digest(&mut self, pos: Position<F>, element: &[u8]) -> Self::Digest {
        let inner = self.inner();
        inner.update(&(*pos).to_be_bytes());
        inner.update(element);
        inner.finalize()
    }

    /// Computes the digest for a node given its position and the digests of its children.
    fn node_digest(
        &mut self,
        pos: Position<F>,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        let inner = self.inner();
        inner.update(&(*pos).to_be_bytes());
        inner.update(left.as_ref());
        inner.update(right.as_ref());
        inner.finalize()
    }

    /// One step of the root fold: `Hash(acc || peak)`.
    ///
    /// This is the fold operation used by some families' [`root`](Self::root) implementations.
    /// It is exposed separately so that proof verification can incrementally fold peaks.
    fn fold_peak(&mut self, acc: &Self::Digest, peak: &Self::Digest) -> Self::Digest {
        let inner = self.inner();
        inner.update(acc.as_ref());
        inner.update(peak.as_ref());
        inner.finalize()
    }

    /// Compute the digest of a byte slice.
    fn digest(&mut self, data: &[u8]) -> Self::Digest {
        let inner = self.inner();
        inner.update(data);
        inner.finalize()
    }
}

/// The standard hasher for Merkle-family structures. Leverages no external data.
pub struct Standard<H: CHasher> {
    hasher: H,
}

impl<H: CHasher> Standard<H> {
    /// Creates a new [Standard] hasher.
    pub fn new() -> Self {
        Self { hasher: H::new() }
    }
}

impl<H: CHasher> Default for Standard<H> {
    fn default() -> Self {
        Self::new()
    }
}
