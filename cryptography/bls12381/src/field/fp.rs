//! Base field arithmetic, by representation.
//!
//! Every representation exchanges elements as [`BYTES`]-byte big-endian integers.

use crate::montgomery;

pub mod unsat49;

/// Number of bytes in an element's big-endian encoding.
pub const BYTES: usize = 48;

/// Number of 64-bit words in an element.
const WORDS: usize = 6;

/// The modulus `p`, little-endian.
const MODULUS: [u64; WORDS] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// Largest lane count of any backend.
pub(crate) const MAX_LANES: usize = 8;

/// Returns `2^k mod p`.
const fn power_of_two(k: u32) -> [u64; WORDS] {
    montgomery::power_of_two(k, &MODULUS)
}

/// Reads a big-endian integer into little-endian words.
fn words_from_bytes(bytes: &[u8; BYTES]) -> [u64; WORDS] {
    let mut words = [0; WORDS];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0.iter().rev()) {
        *word = u64::from_be_bytes(*chunk);
    }
    words
}

/// Writes little-endian words as a big-endian integer.
fn bytes_from_words(words: &[u64; WORDS]) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words.iter().rev()) {
        *chunk = word.to_be_bytes();
    }
    bytes
}

/// Reference arithmetic on canonical integers, for testing representations.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use arbitrary::Unstructured;

    /// A canonical integer below `p`, little-endian.
    pub(crate) type Element = [u64; WORDS];

    /// Zero.
    pub(crate) const ZERO: Element = [0; WORDS];

    /// One.
    pub(crate) const ONE: Element = [1, 0, 0, 0, 0, 0];

    /// `-p^(-1) mod 2^64`.
    const INV: u64 = montgomery::negated_inverse(MODULUS[0]);

    /// `2^768 mod p`, which undoes a Montgomery multiplication's division by `2^384`.
    const R2: Element = power_of_two(768);

    /// Returns `a + b mod p`.
    pub(crate) const fn add(a: Element, b: Element) -> Element {
        montgomery::add(&a, &b, &MODULUS)
    }

    /// Returns `-a mod p`.
    pub(crate) const fn neg(a: Element) -> Element {
        montgomery::neg(&a, &MODULUS)
    }

    /// Returns `a - b mod p`.
    pub(crate) const fn sub(a: Element, b: Element) -> Element {
        add(a, neg(b))
    }

    /// Returns `a * b mod p`, for any `a` below `2^384`.
    pub(crate) const fn mul(a: Element, b: Element) -> Element {
        let product = montgomery::mul(&a, &b, &MODULUS, INV);
        montgomery::mul(&product, &R2, &MODULUS, INV)
    }

    /// Returns `a^(p - 2)`, the inverse of a nonzero `a`.
    pub(crate) fn invert(a: Element) -> Element {
        let mut exponent = MODULUS;
        exponent[0] -= 2;
        let mut result = ONE;
        for word in exponent.iter().rev() {
            for bit in (0..64).rev() {
                result = mul(result, result);
                if (word >> bit) & 1 == 1 {
                    result = mul(result, a);
                }
            }
        }
        result
    }

    /// Returns the residue of a big-endian integer.
    pub(crate) fn reduce(bytes: &[u8; BYTES]) -> Element {
        mul(words_from_bytes(bytes), ONE)
    }

    /// Returns the big-endian encoding of a canonical integer.
    pub(crate) fn to_bytes(a: Element) -> [u8; BYTES] {
        bytes_from_words(&a)
    }

    /// Draws a canonical integer, biased toward values near the modulus.
    pub(crate) fn canonical(u: &mut Unstructured<'_>) -> arbitrary::Result<Element> {
        let mut words: Element = u.arbitrary()?;
        words[WORDS - 1] &= (1 << 61) - 1;
        Ok(if montgomery::is_below(&words, &MODULUS) {
            words
        } else {
            ZERO
        })
    }

    #[test]
    fn reference_arithmetic_is_consistent() {
        let two = add(ONE, ONE);
        assert_eq!(mul(two, invert(two)), ONE);
        assert_eq!(sub(ZERO, ONE), neg(ONE));
        assert_eq!(add(neg(ONE), ONE), ZERO);
        assert_eq!(reduce(&bytes_from_words(&MODULUS)), ZERO);
        assert_eq!(words_from_bytes(&to_bytes(MODULUS)), MODULUS);
    }
}
