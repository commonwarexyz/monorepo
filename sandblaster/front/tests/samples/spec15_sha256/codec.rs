//! A big-endian `u32` reader: the value and the unconsumed rest, `None` on
//! a short input. It refines `spec::codec::read_u32_be` through the view
//! coercion `Option<(u32, &[u8])> ↦ Option<(Nat, Seq<u8>)>` (DESIGN.md
//! §15.3); the coercion is injective, so the refinement determines the
//! function and establishes it for specifications. Proof: PROOF.rs.

use sandblaster::prelude::*;

#[refines(crate::spec::codec::read_u32_be)]
pub fn read_u32_be(xs: &[u8]) -> Option<(u32, &[u8])> {
    if xs.len() < 4 {
        None
    } else {
        Some((u32::from_be_bytes([xs[0], xs[1], xs[2], xs[3]]), &xs[4..]))
    }
}
