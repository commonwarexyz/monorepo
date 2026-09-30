//! The model layer: the code of `merkle.rs` read over numbers. Each exec function listed here
//! carries `#[refines(crate::model::f)]`, which the refinement walk proves in lockstep with the
//! model (no proof text); `PROOF.rs` relates the model to the specification (R7).

use sandblaster::prelude::*;


/// `merkle::Shape` over numbers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Shape { pub height: Nat, pub width: Nat, pub position: Nat, pub index: Nat, pub before: Nat, pub after: Nat }

/// `x.saturating_sub(y)` over numbers.
pub fn sat_sub(x: Nat, y: Nat) -> Nat { if x >= y { x - y } else { 0 } }

pub fn shape(leaves: Nat, index: Nat) -> Option<Shape> {
    if leaves > pow2(62) {
        return None;
    }
    shape_go(63, index, leaves, pow2(62), 0, 0, 0, None)
}

#[decreases(fuel)]
pub fn shape_go(fuel: Nat, target: Nat, remaining: Nat, width: Nat, position: Nat, start: Nat, before: Nat, found: Option<Shape>) -> Option<Shape> {
    if fuel == 0 {
        return found;
    }
    if remaining < width {
        shape_go(fuel - 1, target, remaining, width / 2, position, start, before, found)
    } else {
        let found = if target < start {
            found
        } else if target - start < width {
            Some(Shape { height: fuel - 1, width, position: sat_sub(position + 2 * width, 2), index: target - start, before, after: popcount(remaining - width) })
        } else {
            found
        };
        let next = sat_sub(position + 2 * width, 1);
        shape_go(fuel - 1, target, remaining - width, width / 2, next, start + width, before + 1, found)
    }
}
