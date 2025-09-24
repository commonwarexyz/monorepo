//! Types for representing positions and locations in MMRs.
//!
//! A node's _position_ is its index within the MMR.
//! A node's _location_ is its index within the list of MMR leaves.
//!
//! For example, in an MMR with nodes at positions 0, 1, 2, 3:
//! ```text
//!     2
//!   /   \
//!  0     1     3
//! ```
//! The mapping of location to position is:
//! - Location 0 → Position 0
//! - Location 1 → Position 1  
//! - Location 2 → Position 3
//!
//! (Note that position 2 does not correspond to a location -- it isn't a leaf.)

use core::fmt;
use core::ops::{Add, AddAssign, Sub, SubAssign};

/// A position in an MMR - the index of a node within the MMR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position(pub u64);

/// A location in an MMR - the index of a leaf within the list of MMR leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Location(pub u64);

impl Position {
    /// Create a new position from a u64.
    pub const fn new(pos: u64) -> Self {
        Self(pos)
    }

    /// Get the underlying u64 value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl Location {
    /// Create a new location from a u64.
    pub const fn new(loc: u64) -> Self {
        Self(loc)
    }

    /// Get the underlying u64 value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

// Implement From conversions for ergonomic usage
impl From<u64> for Position {
    fn from(pos: u64) -> Self {
        Self(pos)
    }
}

impl From<Position> for u64 {
    fn from(pos: Position) -> Self {
        pos.0
    }
}

impl From<u64> for Location {
    fn from(loc: u64) -> Self {
        Self(loc)
    }
}

impl From<Location> for u64 {
    fn from(loc: Location) -> Self {
        loc.0
    }
}

// Implement arithmetic operations for convenience
impl Add<u64> for Position {
    type Output = Position;

    fn add(self, rhs: u64) -> Self::Output {
        Position(self.0 + rhs)
    }
}

impl AddAssign<u64> for Position {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Sub<u64> for Position {
    type Output = Position;

    fn sub(self, rhs: u64) -> Self::Output {
        Position(self.0 - rhs)
    }
}

impl SubAssign<u64> for Position {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

impl Add<u64> for Location {
    type Output = Location;

    fn add(self, rhs: u64) -> Self::Output {
        Location(self.0 + rhs)
    }
}

impl AddAssign<u64> for Location {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Sub<u64> for Location {
    type Output = Location;

    fn sub(self, rhs: u64) -> Self::Output {
        Location(self.0 - rhs)
    }
}

impl SubAssign<u64> for Location {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

// Implement Display for better error messages
impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Position({})", self.0)
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Location({})", self.0)
    }
}

/// Convert a position to a location, if the position corresponds to a leaf.
/// Returns None if the position is not a leaf.
pub const fn position_to_location(pos: Position) -> Option<Location> {
    // This is the same logic as the old leaf_pos_to_num function
    let leaf_pos = pos.as_u64();
    if leaf_pos == 0 {
        return Some(Location::new(0));
    }

    let start = u64::MAX >> (leaf_pos + 1).leading_zeros();
    let height = start.trailing_ones();
    let mut two_h = 1 << (height - 1);
    let mut cur_node = start - 1;
    let mut leaf_num_floor = 0u64;

    while two_h > 1 {
        if cur_node == leaf_pos {
            return None;
        }
        let left_pos = cur_node - two_h;
        two_h >>= 1;
        if leaf_pos > left_pos {
            // The leaf is in the right subtree, so we must account for the leaves in the left
            // subtree all of which precede it.
            leaf_num_floor += two_h;
            cur_node -= 1; // move to the right child
        } else {
            // The node is in the left subtree
            cur_node = left_pos;
        }
    }

    Some(Location::new(leaf_num_floor))
}

/// Convert a location to a position.
pub const fn location_to_position(loc: Location) -> Position {
    // This is the same logic as the old leaf_num_to_pos function
    let leaf_num = loc.as_u64();
    // This will never underflow since 2*n >= count_ones(n).
    let pos = leaf_num.checked_mul(2).expect("leaf_num overflow") - leaf_num.count_ones() as u64;
    Position::new(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position_location_conversion() {
        // Test the example from the issue description
        // MMR with nodes at positions 0, 1, 2, 3
        //     2
        //   /   \
        //  0     1     3
        // Location 0 → Position 0
        // Location 1 → Position 1  
        // Location 2 → Position 3

        assert_eq!(location_to_position(Location::new(0)), Position::new(0));
        assert_eq!(location_to_position(Location::new(1)), Position::new(1));
        assert_eq!(location_to_position(Location::new(2)), Position::new(3));

        assert_eq!(position_to_location(Position::new(0)), Some(Location::new(0)));
        assert_eq!(position_to_location(Position::new(1)), Some(Location::new(1)));
        assert_eq!(position_to_location(Position::new(2)), None); // Not a leaf
        assert_eq!(position_to_location(Position::new(3)), Some(Location::new(2)));
    }

    #[test]
    fn test_arithmetic_operations() {
        let pos = Position::new(5);
        assert_eq!(pos + 3, Position::new(8));
        assert_eq!(pos - 2, Position::new(3));

        let mut pos = Position::new(5);
        pos += 3;
        assert_eq!(pos, Position::new(8));
        pos -= 2;
        assert_eq!(pos, Position::new(6));

        let loc = Location::new(10);
        assert_eq!(loc + 5, Location::new(15));
        assert_eq!(loc - 3, Location::new(7));

        let mut loc = Location::new(10);
        loc += 5;
        assert_eq!(loc, Location::new(15));
        loc -= 3;
        assert_eq!(loc, Location::new(12));
    }

    #[test]
    fn test_from_conversions() {
        let pos: Position = 42u64.into();
        assert_eq!(pos, Position::new(42));
        let val: u64 = pos.into();
        assert_eq!(val, 42);

        let loc: Location = 24u64.into();
        assert_eq!(loc, Location::new(24));
        let val: u64 = loc.into();
        assert_eq!(val, 24);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Position::new(123)), "Position(123)");
        assert_eq!(format!("{}", Location::new(456)), "Location(456)");
    }

    #[test]
    fn test_mmr_integration() {
        // Test with a larger MMR to ensure our types work correctly
        // This simulates the example from the issue description
        
        // Test the first few positions and locations
        let test_cases = vec![
            (Location::new(0), Position::new(0)),
            (Location::new(1), Position::new(1)),
            (Location::new(2), Position::new(3)),
            (Location::new(3), Position::new(4)),
            (Location::new(4), Position::new(7)),
            (Location::new(5), Position::new(8)),
            (Location::new(6), Position::new(10)),
            (Location::new(7), Position::new(11)),
            (Location::new(8), Position::new(15)),
            (Location::new(9), Position::new(16)),
        ];

        for (expected_loc, pos) in test_cases {
            // Test position -> location conversion
            let actual_loc = position_to_location(pos);
            assert_eq!(actual_loc, Some(expected_loc), 
                "Position {} should map to Location {}", pos.as_u64(), expected_loc.as_u64());

            // Test location -> position conversion
            let actual_pos = location_to_position(expected_loc);
            assert_eq!(actual_pos, pos,
                "Location {} should map to Position {}", expected_loc.as_u64(), pos.as_u64());
        }

        // Test that non-leaf positions return None
        let non_leaf_positions = vec![
            Position::new(2),  // From the example
            Position::new(5),  // Internal node
            Position::new(6),  // Internal node
            Position::new(9),  // Internal node
            Position::new(12), // Internal node
            Position::new(13), // Internal node
        ];

        for pos in non_leaf_positions {
            assert_eq!(position_to_location(pos), None,
                "Position {} should not be a leaf", pos.as_u64());
        }
    }

    #[test]
    fn test_type_safety() {
        // Demonstrate that the types prevent mixing up positions and locations
        let pos = Position::new(7); // Position 7 is a leaf (location 4)
        let loc = Location::new(3);

        // These should not be equal even with the same underlying value
        assert_ne!(pos.as_u64(), loc.as_u64());

        // Test arithmetic operations work correctly
        let pos_plus_one = pos + 1;
        assert_eq!(pos_plus_one, Position::new(8));

        let loc_plus_one = loc + 1;
        assert_eq!(loc_plus_one, Location::new(4));

        // Test that we can convert between types when needed
        let pos_from_loc = location_to_position(loc);
        let loc_from_pos = position_to_location(pos);

        // These conversions should work
        assert_eq!(pos_from_loc, Position::new(4)); // Location 3 -> Position 4
        assert_eq!(loc_from_pos, Some(Location::new(4))); // Position 7 -> Location 4
    }
}
