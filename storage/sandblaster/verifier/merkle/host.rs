/// `crate::merkle::Error<F>`: the variants the lifted code builds.
#[derive(Debug)]
pub enum Error<F: Family> {
    /// The position does not correspond to a leaf node.
    NonLeaf(super::Position<F>),
    /// The position exceeds the valid range.
    PositionOverflow(super::Position<F>),
    /// The location exceeds the valid range.
    LocationOverflow(super::Location<F>),
}

/// `crate::merkle::Bagging`: how peaks are folded into a root.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Bagging {
    /// Oldest to newest.
    ForwardFold,
    /// Newest to oldest.
    BackwardFold,
}

/// `commonware_cryptography::sha256::Digest`, read as its 32 bytes: the host
/// type is a newtype of `[u8; 32]` whose `Deref<Target = [u8]>` and
/// `AsRef<[u8]>` are those bytes and whose `==` compares them.
pub type Digest = [u8; 32];

/// `commonware_cryptography::Sha256` (the hasher QMDB's Merkle trees use).
pub struct Sha256;

impl CHasher for Sha256 {
    type Digest = [u8; 32];

    /// `Hasher::hash(parts)`: SHA-256 (FIPS 180-4) of the concatenation of
    /// `parts` ("Hash the concatenation of `parts` in a single shot").
    fn hash(parts: &[&[u8]]) -> Digest {
        crate::sha256::sha256_parts(parts)
    }
}
