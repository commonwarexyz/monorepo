//! The smoke probe: one MMR function (`mmr::Family::to_nearest_size`, pilot
//! A's subject), the same text in every subject, out of line.

use storage::merkle::Family as _;

type F = storage::mmr::Family;
type Pos = storage::merkle::Position<F>;

/// `size` at most `MAX_NODES`.
#[inline(never)]
pub fn mmr_to_nearest_size(size: u64) -> u64 {
    F::to_nearest_size(Pos::new(size)).as_u64()
}
