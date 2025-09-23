use super::position::Position;
use core::{convert::TryFrom, fmt};
use thiserror::Error;

/// A [Location] is an index into an MMR's _leaves_.
/// This is in contrast to a [Position], which is an index into an MMR's _nodes_.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug)]
pub struct Location(u64);

impl Location {
    /// Return a new [Location] from a raw `u64`.
    #[inline]
    pub const fn new(loc: u64) -> Self {
        Self(loc)
    }

    /// Return the underlying `u64` value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Return `self + rhs` returning `None` on overflow.
    #[inline]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return `self - rhs` returning `None` on underflow.
    #[inline]
    pub const fn checked_sub(self, rhs: u64) -> Option<Self> {
        match self.0.checked_sub(rhs) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return `self + rhs` saturating at `u64::MAX`.
    #[inline]
    pub const fn saturating_add(self, rhs: u64) -> Self {
        Self(self.0.saturating_add(rhs))
    }

    /// Return `self - rhs` saturating at zero.
    #[inline]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Location({})", self.0)
    }
}

impl From<u64> for Location {
    #[inline]
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<Location> for u64 {
    #[inline]
    fn from(loc: Location) -> Self {
        loc.as_u64()
    }
}

impl TryFrom<Position> for Location {
    type Error = NonLeafPositionError;

    /// Attempt to derive the [Location] of a given node [Position].
    ///
    /// Returns an error if the position does not correspond to an MMR leaf.
    ///
    /// This computation is O(log2(n)) in the given position.
    #[inline]
    fn try_from(pos: Position) -> Result<Self, Self::Error> {
        let pos_u64 = pos.as_u64();
        if pos_u64 == 0 {
            return Ok(Self(0));
        }

        let start = u64::MAX >> (pos_u64 + 1).leading_zeros();
        let height = start.trailing_ones();
        let mut two_h = 1 << (height - 1);
        let mut cur_node = start - 1;
        let mut leaf_loc_floor = 0u64;

        while two_h > 1 {
            if cur_node == pos_u64 {
                return Err(NonLeafPositionError { pos });
            }
            let left_pos = cur_node - two_h;
            two_h >>= 1;
            if pos_u64 > left_pos {
                // The leaf is in the right subtree, so we must account for the leaves in the left
                // subtree all of which precede it.
                leaf_loc_floor += two_h;
                cur_node -= 1; // move to the right child
            } else {
                // The node is in the left subtree
                cur_node = left_pos;
            }
        }

        Ok(Self(leaf_loc_floor))
    }
}

/// Error returned when attempting to interpret a non-leaf position as a [Location].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
#[error("Position({}) is not a leaf", pos.as_u64())]
pub struct NonLeafPositionError {
    pos: Position,
}

impl NonLeafPositionError {
    /// The offending position.
    #[inline]
    pub const fn position(self) -> Position {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::Location;
    use crate::mmr::position::Position;

    // Test that the [Location::try_from] function returns the correct location for leaf positions.
    #[test]
    fn test_try_from_position() {
        const CASES: &[(Position, Location)] = &[
            (Position::new(0), Location::new(0)),
            (Position::new(1), Location::new(1)),
            (Position::new(3), Location::new(2)),
            (Position::new(4), Location::new(3)),
            (Position::new(7), Location::new(4)),
            (Position::new(8), Location::new(5)),
            (Position::new(10), Location::new(6)),
            (Position::new(11), Location::new(7)),
            (Position::new(15), Location::new(8)),
            (Position::new(16), Location::new(9)),
            (Position::new(18), Location::new(10)),
            (Position::new(19), Location::new(11)),
            (Position::new(22), Location::new(12)),
            (Position::new(23), Location::new(13)),
            (Position::new(25), Location::new(14)),
            (Position::new(26), Location::new(15)),
        ];
        for (pos, expected_loc) in CASES {
            let loc = Location::try_from(*pos).expect("should map to a leaf location");
            assert_eq!(loc, *expected_loc);
        }
    }

    // Test that the [Location::try_from] function returns an error for non-leaf positions.
    #[test]
    fn test_try_from_position_error() {
        const CASES: &[Position] = &[
            Position::new(2),
            Position::new(5),
            Position::new(6),
            Position::new(9),
            Position::new(12),
            Position::new(13),
            Position::new(14),
            Position::new(17),
            Position::new(20),
            Position::new(21),
            Position::new(24),
            Position::new(27),
            Position::new(28),
            Position::new(29),
            Position::new(30),
        ];
        for &pos in CASES {
            let err = Location::try_from(pos).expect_err("position is not a leaf");
            assert_eq!(err.position(), pos);
        }
    }

    #[test]
    fn test_checked_add() {
        let loc = Location::new(10);
        assert_eq!(loc.checked_add(5).unwrap().as_u64(), 15);
        assert!(Location::new(u64::MAX).checked_add(1).is_none());
    }

    #[test]
    fn test_checked_sub() {
        let loc = Location::new(10);
        assert_eq!(loc.checked_sub(5).unwrap().as_u64(), 5);
        assert!(loc.checked_sub(11).is_none());
    }

    #[test]
    fn test_saturating_add() {
        let loc = Location::new(10);
        assert_eq!(loc.saturating_add(5).as_u64(), 15);
        assert_eq!(Location::new(u64::MAX).saturating_add(1).as_u64(), u64::MAX);
    }

    #[test]
    fn test_saturating_sub() {
        let loc = Location::new(10);
        assert_eq!(loc.saturating_sub(5).as_u64(), 5);
        assert_eq!(Location::new(0).saturating_sub(1).as_u64(), 0);
    }

    #[test]
    fn test_display() {
        let location = Location::new(42);
        assert_eq!(location.to_string(), "Location(42)");
    }
}
