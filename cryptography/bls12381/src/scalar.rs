//! The scalar field of BLS12-381: integers modulo the prime order `r` of G1 and G2.
//!
//! Only the integer representation needed to drive scalar multiplication exists so far.

/// Number of 64-bit words in a scalar.
const WORDS: usize = 4;

/// Number of bytes in the canonical big-endian encoding.
pub const BYTES: usize = 32;

/// The group order `r` as little-endian words.
const MODULUS: [u64; WORDS] = [
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

/// Width in bits of the windows [`Scalar::window`] exposes.
pub(crate) const WINDOW_BITS: usize = 4;

/// Number of windows in a scalar.
pub(crate) const WINDOWS: usize = WORDS * 64 / WINDOW_BITS;

/// Number of significant bits in a scalar: `r < 2^255`.
pub(crate) const BITS: usize = 255;

/// A canonical integer modulo `r`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar([u64; WORDS]);

impl Scalar {
    /// Zero.
    pub const ZERO: Self = Self([0; WORDS]);

    /// One.
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Converts a canonical little-endian integer into the field.
    ///
    /// Returns `None` when the integer is not below the group order.
    pub const fn from_words(words: [u64; WORDS]) -> Option<Self> {
        let mut borrow = 0;
        let mut i = 0;
        while i < WORDS {
            let wide = (words[i] as u128)
                .wrapping_sub(MODULUS[i] as u128)
                .wrapping_sub(borrow as u128);
            borrow = (wide >> 127) as u64;
            i += 1;
        }
        if borrow == 0 {
            return None;
        }
        Some(Self(words))
    }

    /// Returns the canonical integer as little-endian words.
    pub const fn to_words(self) -> [u64; WORDS] {
        self.0
    }

    /// Parses the canonical big-endian encoding.
    ///
    /// Returns `None` when the encoded integer is not below the group order.
    pub fn from_bytes(bytes: &[u8; BYTES]) -> Option<Self> {
        let mut words = [0; WORDS];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0.iter().rev()) {
            *word = u64::from_be_bytes(*chunk);
        }
        Self::from_words(words)
    }

    /// Returns the canonical big-endian encoding.
    pub fn to_bytes(self) -> [u8; BYTES] {
        let mut bytes = [0; BYTES];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(self.0.iter().rev()) {
            *chunk = word.to_be_bytes();
        }
        bytes
    }

    /// Returns bits `[WINDOW_BITS * index, WINDOW_BITS * (index + 1))` of the integer.
    ///
    /// # Panics
    ///
    /// Panics if `index >= WINDOWS`.
    pub(crate) const fn window(&self, index: usize) -> u8 {
        assert!(index < WINDOWS);
        self.bits(index * WINDOW_BITS, WINDOW_BITS) as u8
    }

    /// Returns `count` bits of the integer starting at bit `start`; bits past the top are zero.
    ///
    /// # Panics
    ///
    /// Panics if `count > 63`.
    pub(crate) const fn bits(&self, start: usize, count: usize) -> u64 {
        assert!(count < 64);
        let mask = (1u64 << count) - 1;
        let (word, shift) = (start / 64, start % 64);
        if word >= WORDS {
            return 0;
        }
        let mut value = self.0[word] >> shift;
        if shift + count > 64 && word + 1 < WORDS {
            value |= self.0[word + 1] << (64 - shift);
        }
        value & mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trip() {
        let mut largest = MODULUS;
        largest[0] -= 1;
        let scalar = Scalar::from_words(largest).unwrap();
        assert_eq!(Scalar::from_bytes(&scalar.to_bytes()), Some(scalar));
        assert!(Scalar::from_words(MODULUS).is_none());
        assert_eq!(Scalar::ONE.to_bytes()[BYTES - 1], 1);
    }

    #[test]
    fn windows_cover_every_bit() {
        let scalar = Scalar([0x0123_4567_89ab_cdef, 0, 0, 0]);
        let digits: Vec<u8> = (0..16).map(|i| scalar.window(i)).collect();
        assert_eq!(digits, [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
        assert_eq!(scalar.window(WINDOWS - 1), 0);
        let scalar = Scalar([u64::MAX, 0x0f, 0, 0]);
        assert_eq!(scalar.bits(60, 8), 0xff);
        assert_eq!(scalar.bits(62, 6), 0x3f);
        assert_eq!(scalar.bits(250, 10), 0);
    }
}
