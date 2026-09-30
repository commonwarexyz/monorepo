//! Shifts against `pow2` (`lemmas/bits_pow2.core`), at the widths the
//! QMDB readers use (`usize` shifts are not covered: each proof enumerates
//! the shift amount, and the file is loaded with every crate).

/// `x >> s` is `x / 2^s`.
#[lemma]
fn shr_is_div_pow2_u8(x: u8, s: u32) {
    requires(s < 8);
    ensures((x >> s) as Nat == x as Nat / pow2(s as Int));
    follows();
}

/// `x >> s` is `x / 2^s`.
#[lemma]
fn shr_is_div_pow2_u16(x: u16, s: u32) {
    requires(s < 16);
    ensures((x >> s) as Nat == x as Nat / pow2(s as Int));
    follows();
}

/// `x >> s` is `x / 2^s`.
#[lemma]
fn shr_is_div_pow2_u32(x: u32, s: u32) {
    requires(s < 32);
    ensures((x >> s) as Nat == x as Nat / pow2(s as Int));
    follows();
}

/// `x >> s` is `x / 2^s`.
#[lemma]
fn shr_is_div_pow2_u64(x: u64, s: u32) {
    requires(s < 64);
    ensures((x >> s) as Nat == x as Nat / pow2(s as Int));
    follows();
}
