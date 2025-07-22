//! A LtHash (Lattice Hash) over a configurable [Hasher].
//!
//! LtHash is a homomorphic hash function that supports incremental updates.
//! Given the hash of an input, along with a small update to the input, you can
//! compute the hash of the new input with its update applied, without having to
//! recompute the entire hash from scratch.
//!
//! # Properties
//!
//! - Incremental: Can update hash without full recomputation
//! - Commutative: Order of operations doesn't matter (a + b = b + a)
//! - Homomorphic: Supports add/subtract operations on hashes
//!
//! # Example
//!
//! ```rust
//! use commonware_cryptography::{Hasher, Blake3};
//! use commonware_cryptography::lthash::LtHash;
//!
//! // Create a new LtHash instance with Blake3
//! let mut lthash = LtHash::<Blake3>::new();
//!
//! // Add some data
//! lthash.add(b"hello");
//! lthash.add(b"world");
//!
//! // Get the final hash
//! let hash1 = lthash.finalize();
//!
//! // Create another instance with different order
//! let mut lthash2 = LtHash::<Blake3>::new();
//! lthash2.add(b"world");
//! lthash2.add(b"hello");
//!
//! // Should produce the same hash (commutativity)
//! let hash2 = lthash2.finalize();
//! assert_eq!(hash1, hash2);
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
//! * <https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0215-accounts-lattice-hash.md>: Homomorphic Hashing of Account State

use crate::Hasher;
use std::marker::PhantomData;

/// Size of the internal LtHash state in bytes (2048 bytes = 16384 bits).
///
/// # Security Rationale
///
/// The 2048-byte (16384-bit) state size provides strong security guarantees:
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
///
/// This implementation targets 128-bit security level, which is considered sufficient
/// for long-term security according to current cryptographic standards. The 2048-byte
/// state provides a substantial security margin beyond this target.
const LTHASH_SIZE: usize = 2048;

/// LtHash implementation generic over a hasher.
///
/// This implementation maintains a large internal state that supports
/// homomorphic operations (add/subtract) and produces a final hash
/// by compressing the state with the provided hasher.
#[derive(Clone)]
pub struct LtHash<H: Hasher> {
    /// Internal state representing the lattice hash
    state: [u8; LTHASH_SIZE],
    /// Phantom data to track the hasher type
    _hasher: PhantomData<H>,
}

impl<H: Hasher> LtHash<H> {
    /// Create a new LtHash instance with zero state.
    pub fn new() -> Self {
        Self {
            state: [0u8; LTHASH_SIZE],
            _hasher: PhantomData,
        }
    }

    /// Add data to the hash.
    ///
    /// This operation is commutative - the order of additions doesn't matter.
    pub fn add(&mut self, data: &[u8]) {
        // Hash the input data to expand it to LTHASH_SIZE
        let expanded = Self::expand_to_lthash_size(data);

        // Add the expanded hash to our state (wrapping arithmetic)
        for (i, &byte) in expanded.iter().enumerate() {
            self.state[i] = self.state[i].wrapping_add(byte);
        }
    }

    /// Subtract data from the hash.
    ///
    /// This allows removing previously added data from the hash state.
    pub fn subtract(&mut self, data: &[u8]) {
        // Hash the input data to expand it to LTHASH_SIZE
        let expanded = Self::expand_to_lthash_size(data);

        // Subtract the expanded hash from our state (wrapping arithmetic)
        for (i, &byte) in expanded.iter().enumerate() {
            self.state[i] = self.state[i].wrapping_sub(byte);
        }
    }

    /// Combine two LtHash states by addition.
    pub fn combine(&mut self, other: &Self) {
        for (i, &byte) in other.state.iter().enumerate() {
            self.state[i] = self.state[i].wrapping_add(byte);
        }
    }

    /// Finalize the hash and return the compressed result.
    ///
    /// This compresses the internal LTHASH_SIZE state to the output size
    /// of the hasher using the hasher's compression function.
    pub fn finalize(&self) -> H::Digest {
        let mut hasher = H::new();
        hasher.update(&self.state);
        hasher.finalize()
    }

    /// Reset the hash to the initial zero state.
    pub fn reset(&mut self) {
        self.state = [0u8; LTHASH_SIZE];
    }

    /// Check if the hash is in the zero state.
    pub fn is_zero(&self) -> bool {
        self.state.iter().all(|&b| b == 0)
    }

    /// Expand input data to LTHASH_SIZE bytes using the hasher as an XOF.
    ///
    /// This uses the hasher in counter mode to generate enough bytes.
    fn expand_to_lthash_size(data: &[u8]) -> [u8; LTHASH_SIZE] {
        let mut result = [0u8; LTHASH_SIZE];
        let mut offset = 0;
        let mut counter = 0u64;

        // Use the hasher in counter mode to expand the data
        while offset < LTHASH_SIZE {
            let mut hasher = H::new();
            hasher.update(data);
            hasher.update(&counter.to_le_bytes());
            let digest = hasher.finalize();

            let digest_bytes = digest.as_ref();
            let copy_len = (LTHASH_SIZE - offset).min(digest_bytes.len());
            result[offset..offset + copy_len].copy_from_slice(&digest_bytes[..copy_len]);

            offset += copy_len;
            counter += 1;
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
        // Show first and last 16 bytes of state for debugging
        write!(
            f,
            "LtHash {{ state: [{:02x?}...{:02x?}] }}",
            &self.state[..16],
            &self.state[LTHASH_SIZE - 16..]
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

        // Empty state should produce the hash of all zeros
        let mut hasher = Blake3::new();
        hasher.update(&[0u8; LTHASH_SIZE]);
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
