//! A homomorphic hash function that enables efficient incremental updates.
//!
//! [LtHash] is an additive homomorphic hash function, meaning that the hash of a sum equals
//! the sum of the hashes: `H(a + b) = H(a) + H(b)`. This enables the efficient addition or
//! removal of elements from a hashed set without recomputing the entire hash from scratch. And
//! unlocks the ability to compare set equality without revealing the entire set or requiring items
//! be added in a specific order.
//!
//! # Key Properties
//!
//! - **Homomorphic**: Supports addition and subtraction of hashes (H(a ± b) = H(a) ± H(b))
//! - **Incremental**: Update existing hashes in O(1) time instead of rehashing everything
//! - **Commutative**: Operation order doesn't matter (H(a) + H(b) = H(b) + H(a))
//! - **Generic**: Works with any cryptographic hash function implementing the [Hasher] trait
//!
//! _If your application requires a (probabilistic) membership check, consider using
//! [crate::bloomfilter] instead._
//!
//! # Example
//!
//! ```rust
//! use commonware_cryptography::{Hasher, Blake3};
//! use commonware_cryptography::lthash::LtHash;
//!
//! // Demonstrate the homomorphic property
//! let mut lthash = LtHash::<Blake3>::new();
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
//! let mut lthash2 = LtHash::<Blake3>::new();
//! lthash2.add(b"alice");
//! lthash2.add(b"charlie");
//!
//! assert_eq!(lthash.finalize(), lthash2.finalize());
//!
//! // Order doesn't matter (commutative property)
//! let mut lthash3 = LtHash::<Blake3>::new();
//! lthash3.add(b"charlie");
//! lthash3.add(b"alice");
//!
//! assert_eq!(lthash2.finalize(), lthash3.finalize());
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
//! * <https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0215-accounts-lattice-hash.md>: Homomorphic Hashing of Account State

use crate::Hasher;
use std::marker::PhantomData;

/// Number of 16-bit integers in the LtHash state.
///
/// Following the construction from "Securing Update Propagation with Homomorphic Hashing",
/// we use 1024 16-bit integers (2048 bytes total) which provides at least 200 bits of security.
const LTHASH_ELEMENTS: usize = 1024;

/// Size of the internal [LtHash] state in bytes.
///
/// The 2048-byte state consists of 1024 16-bit unsigned integers, as specified in
/// "Securing Update Propagation with Homomorphic Hashing". The rationale is as follows:
///
/// 1. **Collision Resistance**: With a 16384-bit state space, finding two different
///    inputs that produce the same LtHash state requires approximately 2^8192
///    operations (birthday paradox), which is computationally infeasible.
///     * <https://cseweb.ucsd.edu/~daniele/papers/IncHash.html>: A new paradigm for collision-free hashing: Incrementality at reduced cost
///
/// 2. **Preimage Resistance**: The large state space makes it infeasible to find
///    an input that produces a specific target hash state.
///    * <https://cseweb.ucsd.edu/~mihir/papers/inc1.pdf>: Incremental Cryptography: The Case of Hashing and Signing
///
/// 3. **Homomorphic Security**: The additive homomorphic property relies on the
///    difficulty of solving the subset sum problem in a large finite group. With
///    16384 bits, even if an attacker knows the final hash and some inputs, finding
///    the remaining inputs is computationally intractable.
///    * <https://dl.acm.org/doi/10.1145/237814.237838>: Generating hard instances of lattice problems
///    * <https://cseweb.ucsd.edu/~daniele/papers/Cyclic.pdf>: Generalized compact knapsacks, cyclic lattices, and efficient one-way functions
///
/// 4. **Protection Against Wagner's Generalized Birthday Attack**: For homomorphic
///    hash functions, Wagner's k-tree algorithm could find collisions in O(2^(n/(1+lg k)))
///    time. With n=16384, even for large k, this remains infeasible.
///    * <https://www.iacr.org/archive/crypto2002/24420288/24420288.pdf>: A Generalized Birthday Problem
const LTHASH_SIZE: usize = 2048;

/// LtHash implementation generic over a hasher.
///
/// This implementation maintains a state of 1024 16-bit unsigned integers that supports
/// homomorphic operations (add/subtract) using modular arithmetic. The construction
/// follows "Securing Update Propagation with Homomorphic Hashing" (IACR 2019/227).
///
/// # Security Warning
///
/// This construction has a known vulnerability: adding the same element 2^16 times
/// will cause overflow and result in the same hash as not adding it at all. For
/// applications where this is a concern, consider adding unique metadata (like indices
/// or timestamps) to each element.
#[derive(Clone)]
pub struct LtHash<H: Hasher> {
    /// Internal state as 1024 16-bit unsigned integers
    state: [u16; LTHASH_ELEMENTS],
    /// Phantom data to track the hasher type
    _hasher: PhantomData<H>,
}

impl<H: Hasher> LtHash<H> {
    /// Create a new LtHash instance with zero state.
    pub fn new() -> Self {
        Self {
            state: [0u16; LTHASH_ELEMENTS],
            _hasher: PhantomData,
        }
    }

    /// Add data to the hash.
    ///
    /// This operation is commutative - the order of additions doesn't matter.
    /// Each element is expanded to 1024 16-bit integers and added component-wise
    /// with modular arithmetic (mod 2^16).
    pub fn add(&mut self, data: &[u8]) {
        // Hash the input data to expand it to LTHASH_ELEMENTS u16s
        let expanded = Self::expand_to_u16_array(data);

        // Add the expanded hash to our state with 16-bit wrapping arithmetic
        for i in 0..LTHASH_ELEMENTS {
            self.state[i] = self.state[i].wrapping_add(expanded[i]);
        }
    }

    /// Subtract data from the hash.
    ///
    /// This allows removing previously added data from the hash state.
    /// Uses 16-bit modular subtraction.
    pub fn subtract(&mut self, data: &[u8]) {
        // Hash the input data to expand it to LTHASH_ELEMENTS u16s
        let expanded = Self::expand_to_u16_array(data);

        // Subtract the expanded hash from our state with 16-bit wrapping arithmetic
        for i in 0..LTHASH_ELEMENTS {
            self.state[i] = self.state[i].wrapping_sub(expanded[i]);
        }
    }

    /// Combine two LtHash states by addition.
    pub fn combine(&mut self, other: &Self) {
        for i in 0..LTHASH_ELEMENTS {
            self.state[i] = self.state[i].wrapping_add(other.state[i]);
        }
    }

    /// Finalize the hash and return the compressed result.
    ///
    /// This compresses the internal state to the output size of the hasher.
    /// The u16 array is converted to little-endian bytes before hashing.
    pub fn finalize(&self) -> H::Digest {
        let mut hasher = H::new();

        // Convert u16 array to bytes in little-endian order
        for &val in &self.state {
            hasher.update(&val.to_le_bytes());
        }

        hasher.finalize()
    }

    /// Reset the hash to the initial zero state.
    pub fn reset(&mut self) {
        self.state = [0u16; LTHASH_ELEMENTS];
    }

    /// Check if the hash is in the zero state.
    pub fn is_zero(&self) -> bool {
        self.state.iter().all(|&val| val == 0)
    }

    /// Expand input data to an array of u16s using the hasher as an XOF.
    ///
    /// This follows the construction from the paper: hash the input to produce
    /// 2048 bytes, then interpret as 1024 little-endian u16 values.
    ///
    /// Note: The reference implementations (Facebook folly, lukechampine/lthash) use
    /// BLAKE2b in XOF mode for expansion. Our implementation uses the provided hasher
    /// in counter mode, which maintains the security properties but produces different
    /// internal states. This means our implementation won't match their test vectors
    /// byte-for-byte, but the homomorphic properties are preserved.
    fn expand_to_u16_array(data: &[u8]) -> [u16; LTHASH_ELEMENTS] {
        let mut result = [0u16; LTHASH_ELEMENTS];
        let mut bytes = [0u8; LTHASH_SIZE];
        let mut offset = 0;
        let mut counter = 0u64;

        // Use the hasher in counter mode to expand the data to LTHASH_SIZE bytes
        while offset < LTHASH_SIZE {
            let mut hasher = H::new();
            hasher.update(data);
            hasher.update(&counter.to_le_bytes());
            let digest = hasher.finalize();

            let digest_bytes = digest.as_ref();
            let copy_len = (LTHASH_SIZE - offset).min(digest_bytes.len());
            bytes[offset..offset + copy_len].copy_from_slice(&digest_bytes[..copy_len]);

            offset += copy_len;
            counter += 1;
        }

        // Convert bytes to u16 array using little-endian interpretation
        for i in 0..LTHASH_ELEMENTS {
            let byte_idx = i * 2;
            result[i] = u16::from_le_bytes([bytes[byte_idx], bytes[byte_idx + 1]]);
        }

        result
    }
}

impl<H: Hasher> Default for LtHash<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hasher> std::fmt::Debug for LtHash<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first and last 8 u16 values for debugging
        write!(
            f,
            "LtHash {{ state: [{:04x?}...{:04x?}] }}",
            &self.state[..8],
            &self.state[LTHASH_ELEMENTS - 8..]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Blake3, Sha256};

    #[test]
    fn test_lthash_new() {
        let lthash = LtHash::<Blake3>::new();
        assert!(lthash.is_zero());
    }

    #[test]
    fn test_lthash_add() {
        let mut lthash = LtHash::<Blake3>::new();
        lthash.add(b"hello");
        assert!(!lthash.is_zero());
    }

    #[test]
    fn test_lthash_commutativity() {
        // Test that a + b = b + a
        let mut lthash1 = LtHash::<Blake3>::new();
        lthash1.add(b"hello");
        lthash1.add(b"world");
        let hash1 = lthash1.finalize();

        let mut lthash2 = LtHash::<Blake3>::new();
        lthash2.add(b"world");
        lthash2.add(b"hello");
        let hash2 = lthash2.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_lthash_associativity() {
        // Test that (a + b) + c = a + (b + c)
        let mut lthash1 = LtHash::<Blake3>::new();
        lthash1.add(b"a");
        lthash1.add(b"b");
        lthash1.add(b"c");
        let hash1 = lthash1.finalize();

        let mut lthash2 = LtHash::<Blake3>::new();
        let mut temp = LtHash::<Blake3>::new();
        temp.add(b"b");
        temp.add(b"c");
        lthash2.add(b"a");
        lthash2.combine(&temp);
        let hash2 = lthash2.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_lthash_subtraction() {
        // Test that (a + b) - b = a
        let mut lthash1 = LtHash::<Blake3>::new();
        lthash1.add(b"hello");
        let hash1 = lthash1.finalize();

        let mut lthash2 = LtHash::<Blake3>::new();
        lthash2.add(b"hello");
        lthash2.add(b"world");
        lthash2.subtract(b"world");
        let hash2 = lthash2.finalize();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_lthash_empty() {
        let lthash = LtHash::<Blake3>::new();
        let empty_hash = lthash.finalize();

        // Empty state should produce the hash of all zero u16s in little-endian
        let mut hasher = Blake3::new();
        for _ in 0..LTHASH_ELEMENTS {
            hasher.update(&0u16.to_le_bytes());
        }
        let expected = hasher.finalize();

        assert_eq!(empty_hash, expected);
    }

    #[test]
    fn test_lthash_reset() {
        let mut lthash = LtHash::<Blake3>::new();
        lthash.add(b"hello");
        assert!(!lthash.is_zero());

        lthash.reset();
        assert!(lthash.is_zero());
    }

    #[test]
    fn test_lthash_different_hashers() {
        // Test with SHA256
        let mut lthash_sha = LtHash::<Sha256>::new();
        lthash_sha.add(b"test");
        let _ = lthash_sha.finalize();

        // Test with Blake3
        let mut lthash_blake = LtHash::<Blake3>::new();
        lthash_blake.add(b"test");
        let _ = lthash_blake.finalize();
    }

    #[test]
    fn test_lthash_large_data() {
        let mut lthash = LtHash::<Blake3>::new();
        let large_data = vec![0xAB; 10000];
        lthash.add(&large_data);
        let _ = lthash.finalize();
    }

    #[test]
    fn test_lthash_many_additions() {
        let mut lthash1 = LtHash::<Blake3>::new();
        for i in 0..100u32 {
            lthash1.add(&i.to_le_bytes());
        }
        let hash1 = lthash1.finalize();

        // Add in reverse order
        let mut lthash2 = LtHash::<Blake3>::new();
        for i in (0..100u32).rev() {
            lthash2.add(&i.to_le_bytes());
        }
        let hash2 = lthash2.finalize();

        // Should be equal due to commutativity
        assert_eq!(hash1, hash2);
    }
}
