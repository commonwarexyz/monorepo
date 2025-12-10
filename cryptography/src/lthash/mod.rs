//! A homomorphic hash function that enables efficient incremental updates.
//!
//! [LtHash] is an additive homomorphic hash function over [crate::Blake3], meaning that the
//! hash of a sum equals the sum of the hashes: `H(a + b) = H(a) + H(b)`. This useful property
//! enables the efficient addition or removal of elements from some hashed set without recomputing
//! the entire hash from scratch. This unlocks the ability to compare set equality without revealing
//! the entire set or requiring items be added in a specific order.
//!
//! # Properties
//!
//! - **Homomorphic**: Supports addition and subtraction of hashes (H(a ± b) = H(a) ± H(b))
//! - **Commutative**: Operation order doesn't matter (H(a) + H(b) = H(b) + H(a))
//! - **Incremental**: Update existing hashes in O(1) time instead of rehashing everything
//!
//! _If your application requires a (probabilistic) membership check, consider using
//! [crate::BloomFilter] instead._
//!
//! # Security
//!
//! [LtHash]'s state consists of 1024 16-bit unsigned integers (2048 bytes), as recommended in
//! "Securing Update Propagation with Homomorphic Hashing". This provides (by their estimates) at
//! least 200 bits of security.
//!
//! # Warning
//!
//! This construction has a known vulnerability: adding the same element 2^16 times
//! will cause overflow and result in the same hash as not adding it at all. For
//! applications where this is a concern, consider adding unique metadata (like indices
//! or timestamps) to each element.
//!
//! # Example
//!
//! ```rust
//! use commonware_cryptography::lthash::LtHash;
//!
//! // Demonstrate the homomorphic property
//! let mut lthash = LtHash::new();
//!
//! // Add elements to our set
//! lthash.add(b"alice");
//! lthash.add(b"bob");
//! lthash.add(b"charlie");
//!
//! // Remove an element (homomorphic subtraction)
//! lthash.subtract(b"bob");
//!
//! // This is equivalent to just adding alice and charlie
//! let mut lthash2 = LtHash::new();
//! lthash2.add(b"alice");
//! lthash2.add(b"charlie");
//!
//! assert_eq!(lthash.checksum(), lthash2.checksum());
//!
//! // Order doesn't matter (commutative property)
//! let mut lthash3 = LtHash::new();
//! lthash3.add(b"charlie");
//! lthash3.add(b"alice");
//!
//! assert_eq!(lthash2.checksum(), lthash3.checksum());
//! ```
//!
//! # Acknowledgements
//!
//! The following resources were used as references when implementing this crate:
//!
//! * <https://cseweb.ucsd.edu/~daniele/papers/IncHash.html>: A new paradigm for collision-free hashing: Incrementality at reduced cost
//! * <https://cseweb.ucsd.edu/~mihir/papers/inc1.pdf>: Incremental Cryptography: The Case of Hashing and Signing
//! * <https://cseweb.ucsd.edu/~daniele/papers/Cyclic.pdf>: Generalized compact knapsacks, cyclic lattices, and efficient one-way functions
//! * <https://dl.acm.org/doi/10.1145/237814.237838>: Generating hard instances of lattice problems
//! * <https://eprint.iacr.org/2019/227>: Securing Update Propagation with Homomorphic Hashing
//! * <https://engineering.fb.com/2019/03/01/security/homomorphic-hashing/>: Open-sourcing homomorphic hashing to secure update propagation
//! * <https://github.com/facebook/folly/blob/main/folly/crypto/LtHash.cpp>: An open-source C++ library developed and used at Facebook.
//! * <https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0215-accounts-lattice-hash.md>: Homomorphic Hashing of Account State

use crate::{
    blake3::{Blake3, CoreBlake3, Digest},
    Hasher as _,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};

/// Size of the internal [LtHash] state in bytes.
const LTHASH_SIZE: usize = 2048;

/// Number of 16-bit integers in the [LtHash] state.
const LTHASH_ELEMENTS: usize = LTHASH_SIZE / 2; // each u16 is 2 bytes

/// An additive homomorphic hash function over [crate::Blake3].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LtHash {
    /// Internal state as 1024 16-bit unsigned integers
    state: [u16; LTHASH_ELEMENTS],
}

impl LtHash {
    /// Create a new [LtHash] instance with zero state.
    pub const fn new() -> Self {
        Self {
            state: [0u16; LTHASH_ELEMENTS],
        }
    }

    /// Add data.
    ///
    /// The order of additions doesn't matter. Each element is expanded to 1024 16-bit
    /// integers and added component-wise with modular arithmetic (mod 2^16).
    pub fn add(&mut self, data: &[u8]) {
        // Hash the input data to expand it to LTHASH_ELEMENTS u16s
        let expanded = Self::expand_to_state(data);

        // Add the expanded hash to our state with 16-bit wrapping arithmetic
        for (i, val) in expanded.iter().enumerate() {
            self.state[i] = self.state[i].wrapping_add(*val);
        }
    }

    /// Subtract data.
    ///
    /// This allows removing previously added data from the hash state. Uses 16-bit
    /// modular subtraction.
    pub fn subtract(&mut self, data: &[u8]) {
        // Hash the input data to expand it to LTHASH_ELEMENTS u16s
        let expanded = Self::expand_to_state(data);

        // Subtract the expanded hash from our state with 16-bit wrapping arithmetic
        for (i, val) in expanded.iter().enumerate() {
            self.state[i] = self.state[i].wrapping_sub(*val);
        }
    }

    /// Combine two [LtHash] states by addition.
    pub fn combine(&mut self, other: &Self) {
        for (i, val) in other.state.iter().enumerate() {
            self.state[i] = self.state[i].wrapping_add(*val);
        }
    }

    /// Return the [Digest] of the current state.
    pub fn checksum(&self) -> Digest {
        let mut hasher = Blake3::new();

        // Convert u16 array to bytes in little-endian order
        for &val in &self.state {
            hasher.update(&val.to_le_bytes());
        }

        hasher.finalize()
    }

    /// Reset the [LtHash] to the initial zero state.
    pub const fn reset(&mut self) {
        self.state = [0u16; LTHASH_ELEMENTS];
    }

    /// Check if the [LtHash] is in the zero state.
    pub fn is_zero(&self) -> bool {
        self.state.iter().all(|&val| val == 0)
    }

    /// Expand input data to an array of u16s using [Blake3] as an XOF.
    fn expand_to_state(data: &[u8]) -> [u16; LTHASH_ELEMENTS] {
        let mut result = [0u16; LTHASH_ELEMENTS];
        let mut bytes = [0u8; LTHASH_SIZE];

        // Use Blake3 in XOF mode to expand the data to LTHASH_SIZE bytes
        let mut hasher = CoreBlake3::new();
        hasher.update(data);
        let mut output_reader = hasher.finalize_xof();
        output_reader.fill(&mut bytes);

        // Convert bytes to u16 array using little-endian interpretation
        for (i, chunk) in bytes.chunks(2).enumerate() {
            result[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }

        result
    }
}

impl Default for LtHash {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for LtHash {
    fn write(&self, buf: &mut impl BufMut) {
        for &val in &self.state {
            val.write(buf);
        }
    }
}

impl Read for LtHash {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let mut state = [0u16; LTHASH_ELEMENTS];
        for val in state.iter_mut() {
            *val = u16::read(buf)?;
        }
        Ok(Self { state })
    }
}

impl FixedSize for LtHash {
    const SIZE: usize = LTHASH_SIZE;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hasher;

    #[test]
    fn test_new() {
        let lthash = LtHash::new();
        assert!(lthash.is_zero());
    }

    #[test]
    fn test_add() {
        let mut lthash = LtHash::new();
        lthash.add(b"hello");
        assert!(!lthash.is_zero());
    }

    #[test]
    fn test_commutativity() {
        // Test that a + b = b + a
        let mut lthash1 = LtHash::new();
        lthash1.add(b"hello");
        lthash1.add(b"world");
        let hash1 = lthash1.checksum();

        let mut lthash2 = LtHash::new();
        lthash2.add(b"world");
        lthash2.add(b"hello");
        let hash2 = lthash2.checksum();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_associativity() {
        // Test that (a + b) + c = a + (b + c)
        let mut lthash1 = LtHash::new();
        lthash1.add(b"a");
        lthash1.add(b"b");
        lthash1.add(b"c");
        let hash1 = lthash1.checksum();

        let mut lthash2 = LtHash::new();
        let mut temp = LtHash::new();
        temp.add(b"b");
        temp.add(b"c");
        lthash2.add(b"a");
        lthash2.combine(&temp);
        let hash2 = lthash2.checksum();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_subtraction() {
        // Test that (a + b) - b = a
        let mut lthash1 = LtHash::new();
        lthash1.add(b"hello");
        let hash1 = lthash1.checksum();

        let mut lthash2 = LtHash::new();
        lthash2.add(b"hello");
        lthash2.add(b"world");
        lthash2.subtract(b"world");
        let hash2 = lthash2.checksum();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_empty() {
        let lthash = LtHash::new();
        let empty_hash = lthash.checksum();

        // Empty state should produce the hash of all zero u16s in little-endian
        let mut hasher = Blake3::new();
        for _ in 0..LTHASH_ELEMENTS {
            hasher.update(&0u16.to_le_bytes());
        }
        let expected = hasher.finalize();

        assert_eq!(empty_hash, expected);
    }

    #[test]
    fn test_reset() {
        let mut lthash = LtHash::new();
        lthash.add(b"hello");
        assert!(!lthash.is_zero());

        lthash.reset();
        assert!(lthash.is_zero());
    }

    #[test]
    fn test_deterministic() {
        let mut lthash = LtHash::new();
        lthash.add(b"test");

        let mut lthash2 = LtHash::new();
        lthash2.add(b"test");
        assert_eq!(lthash.checksum(), lthash2.checksum());
    }

    #[test]
    fn test_large_data() {
        let mut lthash = LtHash::new();
        let large_data = vec![0xAB; 10000];
        lthash.add(&large_data);
        lthash.checksum();
    }

    #[test]
    fn test_snake() {
        let mut lthash1 = LtHash::new();
        for i in 0..100u32 {
            lthash1.add(&i.to_le_bytes());
        }
        let hash1 = lthash1.checksum();

        // Add in reverse order
        let mut lthash2 = LtHash::new();
        for i in (0..100u32).rev() {
            lthash2.add(&i.to_le_bytes());
        }
        let hash2 = lthash2.checksum();

        // Should be equal due to commutativity
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_codec() {
        let mut lthash = LtHash::new();
        lthash.add(b"hello");
        let hash = lthash.checksum();

        let mut buf = Vec::new();
        lthash.write(&mut buf);
        let lthash2 = LtHash::read_cfg(&mut &buf[..], &()).unwrap();
        let hash2 = lthash2.checksum();
        assert_eq!(hash, hash2);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;

        commonware_codec::conformance_tests! {
            LtHash,
        }
    }
}
