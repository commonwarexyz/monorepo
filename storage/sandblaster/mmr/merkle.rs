//! `crate::merkle` of commonware-storage, as far as the lifted files use
//! it: the lifted modules (the host's own files, `in_place`), the model of
//! the host enum they build, and the re-exports of `merkle/mod.rs`.

// `Position` and `Location` are generic over the open trait `Family`: they
// are verified at the MMR (`mmr::Family`); at the MMB they stay unchecked
// host code. Formatting, hashing and the codec impls (which delegate to
// commonware-codec's varint) stay host code, listed.
#[lift(mir = "mmr.sbmir", in_place, instance = "Family: crate::merkle::mmr::Family, Graftable: crate::merkle::mmr::Family", unverified_instances = "Family: crate::merkle::mmb::Family, Graftable: crate::merkle::mmb::Family", unverified_impls = "commonware_codec::Write, commonware_codec::EncodeSize, commonware_codec::Read")]
#[path = "../../src/merkle/position.rs"]
pub mod position;

// `LocationRangeExt` stays host code too: its one impl is on core's
// `Range<Location>`, a type outside the lifted files, and turns it into a
// `Range<usize>` for slice indexing (`as usize`, the target's width).
#[lift(mir = "mmr.sbmir", in_place, instance = "Family: crate::merkle::mmr::Family, Graftable: crate::merkle::mmr::Family", unverified_impls = "commonware_codec::Write, commonware_codec::EncodeSize, commonware_codec::Read, LocationRangeExt")]
#[path = "../../src/merkle/location.rs"]
pub mod location;

// Two functions stay unchecked host code (listed in the record):
// `subtree_root_position` and `leftmost_leaf`: the prover does not yet
// close their `checked_shl(..).expect(..)` and
// `checked_add(..).and_then(..).expect(..)` chains. No law yet justifies
// `leftmost_leaf`'s final `expect`: `position_to_location_is_complete`
// needs the position written as `mmr_size(loc)`, and `leftmost_leaf` has it
// as `pos + 2 - 2^(height+1)`.
#[lift(mir = "mmr.sbmir", in_place, children = "iterator", instance = "Family: crate::merkle::mmr::Family, Graftable: crate::merkle::mmr::Family", unverified_fns = "Family::subtree_root_position, Family::leftmost_leaf")]
#[path = "../../src/merkle/mmr/mod.rs"]
pub mod mmr;

// a model of the host's `crate::merkle::Error` (the variants the lifted
// code builds)
#[lift(host, instance = "Family: crate::merkle::mmr::Family")]
mod host;

pub use host::Error;
pub use location::Location;
pub use position::Position;
