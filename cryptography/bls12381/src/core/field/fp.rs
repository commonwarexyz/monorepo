//! Base field arithmetic, by representation.
//!
//! Every representation exchanges elements as [`BYTES`]-byte big-endian integers.

use crate::montgomery;

pub mod rns;
pub mod unsat28;
pub mod unsat49;

/// Number of bytes in an element's big-endian encoding.
pub const BYTES: usize = 48;

/// Number of 64-bit words in an element.
pub(crate) const WORDS: usize = 6;

/// The modulus `p`, little-endian.
pub(crate) const MODULUS: [u64; WORDS] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// Largest lane count of any backend.
pub(crate) const MAX_LANES: usize = 8;

/// The encoding of one.
pub(crate) const ONE: [u8; BYTES] = encode([1, 0, 0, 0, 0, 0]);

/// `p - 1`, the encoding of `-1`.
pub(crate) const MINUS_ONE: [u8; BYTES] = {
    let mut bytes = encode(MODULUS);
    // The modulus is odd, so its low byte does not borrow.
    bytes[BYTES - 1] -= 1;
    bytes
};

/// Returns the encoding of an element given as little-endian words.
pub(crate) const fn encode(words: [u64; WORDS]) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    let mut i = 0;
    while i < BYTES {
        bytes[i] = (words[WORDS - 1 - i / 8] >> (56 - 8 * (i % 8))) as u8;
        i += 1;
    }
    bytes
}

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
    for (chunk, word) in bytes
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(words.iter().rev())
    {
        *chunk = word.to_be_bytes();
    }
    bytes
}

/// Returns `p - a` for a canonical big-endian element `a`, mapping zero to zero.
pub(crate) fn neg(a: &[u8; BYTES]) -> [u8; BYTES] {
    bytes_from_words(&montgomery::neg(&words_from_bytes(a), &MODULUS))
}

/// Splits a little-endian integer below `2^384` into `N` limbs of `BITS` bits.
const fn limbs_from_words<const N: usize, const BITS: u32>(words: [u64; WORDS]) -> [u64; N] {
    let bits = BITS as usize;
    let mask = (1 << BITS) - 1;
    let mut limbs = [0; N];
    let mut i = 0;
    while i < N {
        let (word, shift) = (i * bits / 64, i * bits % 64);
        let mut limb = 0;
        if word < WORDS {
            limb = words[word] >> shift;
            if shift + bits > 64 && word + 1 < WORDS {
                limb |= words[word + 1] << (64 - shift);
            }
        }
        limbs[i] = limb & mask;
        i += 1;
    }
    limbs
}

/// Joins `N` carried limbs of `BITS` bits, holding a value below `2^384`, into little-endian
/// 64-bit words.
const fn words_from_limbs<const N: usize, const BITS: u32>(limbs: [u64; N]) -> [u64; WORDS] {
    let bits = BITS as usize;
    let mut words = [0u64; WORDS + 1];
    let mut i = 0;
    while i < N {
        let (word, shift) = (i * bits / 64, i * bits % 64);
        words[word] |= limbs[i] << shift;
        if shift + bits > 64 {
            words[word + 1] |= limbs[i] >> (64 - shift);
        }
        i += 1;
    }
    let mut out = [0; WORDS];
    let mut i = 0;
    while i < WORDS {
        out[i] = words[i];
        i += 1;
    }
    out
}

/// Returns `k * p` in `N` carried limbs of `BITS` bits.
const fn multiple<const N: usize, const BITS: u32>(k: u64) -> [u64; N] {
    let modulus = limbs_from_words::<N, BITS>(MODULUS);
    let mask = (1 << BITS) - 1;
    let mut limbs = [0; N];
    let mut carry = 0u128;
    let mut i = 0;
    while i < N {
        let wide = modulus[i] as u128 * k as u128 + carry;
        limbs[i] = wide as u64 & mask;
        carry = wide >> BITS;
        i += 1;
    }
    assert!(carry == 0);
    limbs
}

/// Returns `k * p` in `N` limbs of `BITS` bits, with twice `2^BITS` moved from each limb into
/// the one below it.
///
/// Every limb but the top one is then at least twice `2^BITS`, so subtracting a value whose limbs
/// are at most twice those of a carried value never borrows from them. The top limb is two less
/// than that of `k * p`, which still covers the top limb of such a value below `(k - 1) * p`:
/// the two differ by more than `p`, which exceeds three units of the top limb.
const fn bias<const N: usize, const BITS: u32>(k: u64) -> [u64; N] {
    assert!(k >= 1);
    // p exceeds three units of the top limb, whose weight is at least 2^320.
    assert!(MODULUS[WORDS - 1] >> (BITS as usize * (N - 1) - 320) > 3);
    let mut limbs = multiple::<N, BITS>(k);
    let mut i = 0;
    while i + 1 < N {
        assert!(limbs[i + 1] >= 2);
        limbs[i] += 2 << BITS;
        limbs[i + 1] -= 2;
        i += 1;
    }
    limbs
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
