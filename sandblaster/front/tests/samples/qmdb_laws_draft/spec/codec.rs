//! Stub of a proof's bytes: the location as a minimal LEB128 varint.

use super::proof::Proof;

/// Minimal LEB128.
#[decreases(x)]
pub fn varint(x: Nat) -> Seq<u8> {
    if x < 128 { seq![x as u8] } else { seq![(128 + x % 128) as u8, ..varint(x / 128)] }
}

/// The encoding (stub: the location only).
pub fn encode(p: Proof) -> Seq<u8> {
    varint(p.location)
}

/// Reads a varint.
#[decreases(b.len())]
pub fn uint(b: Seq<u8>) -> Option<(Nat, Seq<u8>)> {
    if b.len() == 0 {
        None
    } else if b[0] < 128 {
        Some((b[0] as Nat, b.skip(1)))
    } else {
        match uint(b.skip(1)) {
            Some((x, rest)) => Some((b[0] as Nat - 128 + 128 * x, rest)),
            None => None,
        }
    }
}

/// The decoding (stub).
pub fn decode(b: Seq<u8>) -> Option<(Proof, Seq<u8>)> {
    match uint(b) {
        Some((location, rest)) => Some((Proof { location, chunk: [0u8; 32], leaves: location + 1, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }, rest)),
        None => None,
    }
}
