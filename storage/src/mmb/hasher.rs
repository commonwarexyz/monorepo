//! Decorator for a cryptographic hasher that implements the MMB-specific hashing logic.

use super::{Location, Position};
use commonware_cryptography::{Digest, Hasher as CHasher};

/// A trait for computing the various digests of an MMB.
pub trait Hasher: Send + Sync {
    type Digest: Digest;
    type Inner: commonware_cryptography::Hasher<Digest = Self::Digest>;

    /// Computes the digest for a leaf given its position and the element it represents.
    fn leaf_digest(&mut self, pos: Position, element: &[u8]) -> Self::Digest;

    /// Computes the digest for a node given its position and the digests of its children.
    fn node_digest(
        &mut self,
        pos: Position,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest;

    /// Computes the root for an MMB by left-folding peak digests from oldest to newest.
    ///
    /// The leaf count is hashed first, then peaks are folded: `hash(hash(hash(leaves, oldest),
    /// next), ..., newest)`. The `peak_digests` iterator must yield digests from oldest (tallest)
    /// to newest (shortest).
    fn root<'a>(
        &mut self,
        leaves: Location,
        peak_digests: impl Iterator<Item = &'a Self::Digest>,
    ) -> Self::Digest;

    /// One step of the root fold: `Hash(acc || peak)`.
    ///
    /// This is the fold operation used by [`root`](Self::root). It is exposed separately so that
    /// proof verification can incrementally fold peaks without recomputing `Hash(leaves)`.
    fn fold_peak(&mut self, acc: &Self::Digest, peak: &Self::Digest) -> Self::Digest;

    /// Compute the digest of a byte slice.
    fn digest(&mut self, data: &[u8]) -> Self::Digest;

    /// Access the inner [CHasher] hasher.
    fn inner(&mut self) -> &mut Self::Inner;

    /// Fork the hasher to provide equivalent functionality in another thread. This is different
    /// than [Clone::clone] because the forked hasher need not be a deep copy, and may share non-mutable
    /// state with the hasher from which it was forked.
    fn fork(&self) -> impl Hasher<Digest = Self::Digest>;
}

/// The standard hasher to use with an MMB for computing leaf, node and root digests. Leverages no
/// external data.
pub struct Standard<H: CHasher> {
    hasher: H,
}

impl<H: CHasher> Standard<H> {
    /// Creates a new [Standard] hasher.
    pub fn new() -> Self {
        Self { hasher: H::new() }
    }

    pub fn update_with_pos(&mut self, pos: Position) {
        let pos = *pos;
        self.hasher.update(&pos.to_be_bytes());
    }

    pub fn update_with_digest(&mut self, digest: &H::Digest) {
        self.hasher.update(digest.as_ref());
    }

    pub fn update_with_element(&mut self, element: &[u8]) {
        self.hasher.update(element);
    }

    pub fn finalize(&mut self) -> H::Digest {
        self.hasher.finalize()
    }
}

impl<H: CHasher> Default for Standard<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: CHasher> Hasher for Standard<H> {
    type Digest = H::Digest;
    type Inner = H;

    fn inner(&mut self) -> &mut H {
        &mut self.hasher
    }

    fn fork(&self) -> impl Hasher<Digest = H::Digest> {
        Self { hasher: H::new() }
    }

    fn leaf_digest(&mut self, pos: Position, element: &[u8]) -> H::Digest {
        self.update_with_pos(pos);
        self.update_with_element(element);
        self.finalize()
    }

    fn node_digest(&mut self, pos: Position, left: &H::Digest, right: &H::Digest) -> H::Digest {
        self.update_with_pos(pos);
        self.update_with_digest(left);
        self.update_with_digest(right);
        self.finalize()
    }

    fn root<'a>(
        &mut self,
        leaves: Location,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        let mut acc = self.digest(&leaves.as_u64().to_be_bytes());
        for digest in peak_digests {
            acc = self.fold_peak(&acc, digest);
        }
        acc
    }

    fn fold_peak(&mut self, acc: &H::Digest, peak: &H::Digest) -> H::Digest {
        self.update_with_digest(acc);
        self.update_with_digest(peak);
        self.finalize()
    }

    fn digest(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.update(data);
        self.finalize()
    }
}
