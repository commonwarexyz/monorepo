//! The instances the verifier's MIR is extracted at (`verifier.sbmir`;
//! `sandblaster/mirx/extract.sh --inject instances=<this file> --instance
//! ..`, `docs/mir-lift.md` §20.1). The extraction compiles this file as
//! `mod instances;` of the crate root, so rustc resolves each type; the
//! build never compiles it. They are the instances `merkle.rs` declares:
//! the open traits the lifted files are generic over, each read at one type
//! (SEMANTICS.md §19.6).

/// `Hasher: crate::merkle::hasher::Standard`, at SHA-256 (QMDB's hasher).
pub type Hasher = crate::merkle::hasher::Standard<commonware_cryptography::Sha256>;

/// `CHasher: crate::merkle::host::Sha256`: commonware's SHA-256, whose
/// `hash` the host model `host::Sha256` states.
pub type Sha256 = commonware_cryptography::Sha256;

/// `Digest: crate::merkle::host::Digest`: commonware's SHA-256 digest (a
/// newtype of its 32 bytes, read as them: the host model `host::Digest`).
pub type Digest = commonware_cryptography::sha256::Digest;

/// The elements `Subtree::reconstruct_digest` hashes (`E: Iterator<Item:
/// AsRef<[u8]>>`): a byte-string iterator over a fixed list, yielding the
/// byte strings themselves. Its `next` is read as the lift prelude's
/// `bytes_iter_next` on the list not yet yielded (SEMANTICS.md §19.10's
/// state model of such an iterator).
pub type Elements = core::iter::Copied<core::slice::Iter<'static, &'static [u8]>>;
