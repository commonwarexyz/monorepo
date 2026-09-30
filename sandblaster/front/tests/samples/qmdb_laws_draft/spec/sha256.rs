//! Stub of SHA-256: a digest that depends on every byte (recursively, like the real one).

/// A digest (32 bytes).
pub type Digest = [u8; 32];

/// The byte sum of a message.
#[decreases(m.len())]
pub fn weight(m: Seq<u8>) -> Nat {
    if m.len() == 0 { 0 } else { m[0] as Nat + weight(m.skip(1)) }
}

/// The stub digest.
pub fn sha256(m: Seq<u8>) -> Digest {
    if weight(m) % 2 == 0 { [0u8; 32] } else { [1u8; 32] }
}

/// A SHA-256 collision: two different messages with one digest.
pub fn collision(c: Option<(Seq<u8>, Seq<u8>)>) -> bool {
    match c {
        Some((x, y)) => x != y && sha256(x) == sha256(y),
        None => false,
    }
}

/// Finding a collision is infeasible.
#[assumption(class = computational, cite = "SHA-256 collision resistance; NIST SP 800-107 Rev. 1, §4.1")]
pub fn collision_resistance() {}
