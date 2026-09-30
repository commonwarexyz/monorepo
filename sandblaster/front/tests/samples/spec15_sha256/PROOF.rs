//! Proofs of the refinements that need a step of their own.

/// The implementation and the reference compute the same word function in
/// different ways; the word-algebra normalizer decides the equation
/// (DESIGN.md §9.8).
#[proof(refines = crate::sha::compress)]
fn compress(state: [u32; 8], block: &[u8; 64]) {
    bv();
}

/// `u32::from_be_bytes` is the positional value of its bytes: the word
/// equation is decided by the normalizer.
#[lemma]
fn be_word(a: u8, b: u8, c: u8, d: u8) {
    ensures(u32::from_be_bytes([a, b, c, d]) == (a as u32) * 16777216u32 + (b as u32) * 65536u32 + (c as u32) * 256u32 + (d as u32));
    bv();
}

/// The reader refines the positional reference: on a short input both are
/// `None`; otherwise the value is the positional sum of the first four bytes
/// (`be_word`, then arithmetic) and the rest is the same suffix.
#[proof(refines = crate::codec::read_u32_be)]
fn read_u32_be(xs: &[u8]) {
    // a codec reader is opaque in proofs (DESIGN.md §5.6): unfold it here
    unfold(crate::codec::read_u32_be);
    if xs.len() < 4 {
        follows();
    } else {
        be_word(xs[0], xs[1], xs[2], xs[3]);
        follows();
    }
}
