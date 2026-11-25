//! Helpers shared by the proofs.

use commonware_storage::merkle::{Family, Location, Position};

/// An implementation-consistency check: an assertion that is STRONGER than the documented
/// contract.
///
/// It is compiled into the proof only with `--features consistency`. The default build (the
/// contract gate) does not assert it, so a valid change of the implementation cannot fail the
/// gate through one of these.
macro_rules! consistency {
    ($($arg:tt)*) => {
        if cfg!(feature = "consistency") {
            assert!($($arg)*);
        }
    };
}
pub(crate) use consistency;

/// The largest valid leaf count of the family, as a `u64`.
pub fn max_leaves<F: Family>() -> u64 {
    F::MAX_LEAVES.as_u64()
}

/// The largest valid node count of the family, as a `u64`.
pub fn max_nodes<F: Family>() -> u64 {
    F::MAX_NODES.as_u64()
}

/// The size of a structure with `n` leaves: `location_to_position` read as a count.
pub fn size_for<F: Family>(n: u64) -> u64 {
    F::location_to_position(Location::<F>::new(n)).as_u64()
}

/// `position_to_location` on a raw `u64`.
pub fn leaves_for<F: Family>(pos: u64) -> Option<u64> {
    F::position_to_location(Position::<F>::new(pos)).map(Location::as_u64)
}

/// Any leaf count in the public domain `0..=MAX_LEAVES` that is below `limit`.
///
/// `limit` is `u64::MAX` for the full domain.
pub fn any_leaf_count<F: Family>(limit: u64) -> u64 {
    let n: u64 = kani::any();
    kani::assume(n <= max_leaves::<F>());
    kani::assume(n < limit);
    n
}
