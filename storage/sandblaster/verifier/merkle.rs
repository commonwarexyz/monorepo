//! `crate::merkle` of commonware-storage, as far as the lifted verifier
//! files use it: the lifted modules (the host's own files, `in_place`), the
//! models of the host items they name, and the re-exports of
//! `merkle/mod.rs`.

// `Position` and `Location` are generic over the open trait `Family`: they
// are verified at the MMR (`mmr::Family`); at the MMB they stay unchecked
// host code. Formatting, hashing and the codec impls (which delegate to
// commonware-codec's varint) stay host code, listed.
#[lift(in_place, instance = "Family: crate::merkle::mmr::Family, Graftable: crate::merkle::mmr::Family", unverified_instances = "Family: crate::merkle::mmb::Family, Graftable: crate::merkle::mmb::Family", unverified_impls = "commonware_codec::Write, commonware_codec::EncodeSize, commonware_codec::Read", unverified_fns = "Position::is_valid_size")]
#[path = "../../src/merkle/position.rs"]
pub mod position;

#[lift(in_place, instance = "Family: crate::merkle::mmr::Family, Graftable: crate::merkle::mmr::Family", unverified_impls = "commonware_codec::Write, commonware_codec::EncodeSize, commonware_codec::Read, LocationRangeExt", unverified_fns = "Location::try_from")]
#[path = "../../src/merkle/location.rs"]
pub mod location;

// Only what the first set calls: `children` and the leaf/position
// conversions (`location.rs` calls them). The peak iterator and the rest of
// the family are verified by `sandblaster/mmr`; here they stay host code
// (listed), until the verifier's next set needs them.
#[lift(in_place, instance = "Family: crate::merkle::mmr::Family, Graftable: crate::merkle::mmr::Family", unverified_fns = "Family::position_to_location, Family::to_nearest_size, Family::peaks, Family::parent_heights, Family::pos_to_height, Family::is_valid_size, Family::chunk_peaks, Family::subtree_root_position, Family::leftmost_leaf")]
#[path = "../../src/merkle/mmr/mod.rs"]
pub mod mmr;

// The hashing of Merkle nodes (`hasher.rs`) at QMDB's hasher: the open
// trait `Hasher` at `Standard`, whose hash function `H: CHasher` is SHA-256
// (the host model `host::Sha256`). Its root folding (`root`,
// `root_with_folded_peaks`: generic iterators, the next set) and the SIMD
// pair hash (`node_digest_pair`) stay host code, as does the blanket impl for
// `&T` (another instance).
#[lift(in_place, items = "Hasher, Standard", instance = "Hasher: crate::merkle::hasher::Standard, CHasher: crate::merkle::host::Sha256", unverified_fns = "Hasher::root, Hasher::root_with_folded_peaks, Standard::node_digest_pair")]
#[path = "../../src/merkle/hasher.rs"]
pub mod hasher;

// Range-proof verification (`proof.rs`), first set: a subtree's digest
// rebuilt from the proven elements and the proof's sibling digests
// (`Subtree::reconstruct_digest`, the core every verification entry point
// calls) and its geometry. Digests are SHA-256 digests (`D: Digest` at the
// host model `host::Digest`). The rest of the file (the `Proof` type, its
// codec and entry points, `Blueprint`, pinned-node reconstruction) is the
// next set: host code, listed.
#[lift(in_place, items = "ReconstructionError, Subtree", instance = "Digest: crate::merkle::host::Digest", unverified_fns = "Subtree::collect_siblings, Subtree::collect_prefix_siblings, Subtree::reconstruct_from_pins")]
#[path = "../../src/merkle/proof.rs"]
pub mod proof;

// models of the host items the lifted code names
#[lift(host, instance = "Family: crate::merkle::mmr::Family")]
pub(crate) mod host;

pub use host::{Bagging, Digest, Error};
pub use location::Location;
pub use position::Position;
