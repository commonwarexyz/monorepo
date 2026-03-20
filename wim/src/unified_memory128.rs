//! Unified Memory Model for PolkaVM (128-bit secure version)
//!
//! Program code and data share the same address space with a single merkle root.
//! Uses GF(2^128) for 64-bit security (birthday bound).
//!
//! ## Memory Layout
//!
//! ```text
//! Address Range          | Content         | Access
//! -----------------------|-----------------|--------
//! 0x0000_0000 - CODE_END | Program code    | Read-only
//! CODE_END - HEAP_START  | (reserved)      | None
//! HEAP_START - STACK_END | Heap + Stack    | Read-write
//! ```
//!
//! ## Security Properties
//!
//! - 128-bit field elements provide 64-bit collision resistance
//! - Rescue-Prime hash with proven security
//! - Domain-separated hashing for leaves vs internal nodes
//! - Merkle proofs bind value, position, and root together

use crate::merkle128::{MerkleTree128, MerkleProof128};
use crate::rescue;
use commonware_commitment::field::{BinaryElem128, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Memory layout constants
pub const CODE_START: u32 = 0x0000_0000;
pub const CODE_MAX_SIZE: u32 = 0x0010_0000;  // 1MB for code
pub const HEAP_START: u32 = 0x0010_0000;
pub const STACK_START: u32 = 0x8000_0000;

/// Unified memory with 128-bit merkle authentication
#[derive(Debug, Clone)]
pub struct UnifiedMemory128 {
    /// Underlying merkle tree (values are u128, but we store u32 words)
    tree: MerkleTree128,

    /// Program size in bytes
    program_size: u32,

    /// Total memory size (number of 128-bit words)
    word_count: usize,
}

impl UnifiedMemory128 {
    /// Create unified memory with program loaded at address 0
    ///
    /// Program bytes are loaded starting at CODE_START.
    /// Memory is organized as 128-bit words (16 bytes each).
    pub fn with_program(program_bytes: &[u8], word_count: usize) -> Result<Self, &'static str> {
        if !word_count.is_power_of_two() {
            return Err("word count must be power of 2");
        }

        if program_bytes.len() as u32 > CODE_MAX_SIZE {
            return Err("program too large");
        }

        // Convert bytes to u128 words (little-endian)
        let mut words = vec![0u128; word_count];

        for (i, chunk) in program_bytes.chunks(16).enumerate() {
            if i >= word_count {
                return Err("program too large for memory");
            }
            let mut buf = [0u8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            words[i] = u128::from_le_bytes(buf);
        }

        let tree = MerkleTree128::new(words)?;

        Ok(Self {
            tree,
            program_size: program_bytes.len() as u32,
            word_count,
        })
    }

    /// Get the state root (single commitment for code + data)
    pub fn root(&self) -> BinaryElem128 {
        self.tree.root()
    }

    /// Fetch instruction word at byte offset
    ///
    /// Returns the 128-bit word containing the instruction and a merkle proof.
    pub fn fetch_instruction(&self, byte_offset: u32) -> Result<InstructionFetch128, &'static str> {
        if byte_offset >= self.program_size {
            return Err("byte offset out of program bounds");
        }

        // Word index (16 bytes per word)
        let word_idx = (byte_offset / 16) as usize;

        let proof = self.tree.prove(word_idx)?;

        Ok(InstructionFetch128 {
            byte_offset,
            word_index: word_idx,
            word_value: proof.value,
            merkle_proof: proof,
        })
    }

    /// Read a data word (must be outside code region)
    pub fn read_data(&self, byte_addr: u32) -> Result<(u128, MerkleProof128), &'static str> {
        if byte_addr < HEAP_START {
            return Err("data read in code region");
        }

        let word_idx = (byte_addr / 16) as usize;
        if word_idx >= self.word_count {
            return Err("address out of bounds");
        }

        let proof = self.tree.prove(word_idx)?;
        Ok((proof.value, proof))
    }

    /// Write a data word (must be outside code region)
    pub fn write_data(&mut self, byte_addr: u32, value: u128) -> Result<(), &'static str> {
        if byte_addr < HEAP_START {
            return Err("cannot write to code region");
        }

        let word_idx = (byte_addr / 16) as usize;
        if word_idx >= self.word_count {
            return Err("address out of bounds");
        }

        self.tree.write(word_idx, value)
    }
}

/// Instruction fetch result with merkle proof
#[derive(Debug, Clone)]
pub struct InstructionFetch128 {
    /// Byte offset of the instruction
    pub byte_offset: u32,

    /// Word index in the tree
    pub word_index: usize,

    /// The 128-bit word containing the instruction
    pub word_value: u128,

    /// Merkle proof binding value to root
    pub merkle_proof: MerkleProof128,
}

impl InstructionFetch128 {
    /// Verify this fetch against an expected root
    pub fn verify(&self, expected_root: BinaryElem128) -> bool {
        self.merkle_proof.root == expected_root && self.merkle_proof.verify()
    }

    /// Extract u32 instruction at byte offset within the 128-bit word
    pub fn extract_u32(&self, byte_within_word: u32) -> u32 {
        let shift = (byte_within_word % 16) * 8;
        ((self.word_value >> shift) & 0xFFFFFFFF) as u32
    }
}

/// Constraint for instruction fetch verification
///
/// Evaluates to zero iff the instruction fetch is valid.
#[derive(Debug, Clone)]
pub struct InstructionFetchConstraint128 {
    /// Word index in the tree
    pub word_index: usize,

    /// Expected word value
    pub word_value: BinaryElem128,

    /// Merkle siblings
    pub siblings: Vec<BinaryElem128>,

    /// Expected root
    pub expected_root: BinaryElem128,
}

impl InstructionFetchConstraint128 {
    /// Create constraint from an instruction fetch
    pub fn from_fetch(fetch: &InstructionFetch128) -> Self {
        Self {
            word_index: fetch.word_index,
            word_value: BinaryElem128::from(fetch.word_value),
            siblings: fetch.merkle_proof.siblings.clone(),
            expected_root: fetch.merkle_proof.root,
        }
    }

    /// Evaluate the constraint
    ///
    /// Returns zero iff the merkle proof is valid.
    pub fn evaluate(&self) -> BinaryElem128 {
        // Recompute root from value and siblings
        let mut current = rescue::hash_leaf(self.word_value);
        let mut idx = self.word_index;

        for sibling in &self.siblings {
            if idx % 2 == 0 {
                current = rescue::hash_pair(current, *sibling);
            } else {
                current = rescue::hash_pair(*sibling, current);
            }
            idx /= 2;
        }

        // Constraint: computed_root XOR expected_root = 0
        current.add(&self.expected_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_memory() {
        let program = vec![0u8; 64]; // 64 bytes = 4 words
        let mem = UnifiedMemory128::with_program(&program, 16).unwrap();

        assert_ne!(mem.root(), BinaryElem128::zero());
    }

    #[test]
    fn test_fetch_instruction() {
        // 32 bytes of "program"
        let program: Vec<u8> = (0..32).collect();
        let mem = UnifiedMemory128::with_program(&program, 16).unwrap();
        let root = mem.root();

        // Fetch at byte 0
        let fetch = mem.fetch_instruction(0).unwrap();
        assert!(fetch.verify(root));
        assert_eq!(fetch.word_index, 0);

        // Fetch at byte 16 (second word)
        let fetch = mem.fetch_instruction(16).unwrap();
        assert!(fetch.verify(root));
        assert_eq!(fetch.word_index, 1);
    }

    #[test]
    fn test_fetch_constraint() {
        let program: Vec<u8> = (0..32).collect();
        let mem = UnifiedMemory128::with_program(&program, 16).unwrap();

        let fetch = mem.fetch_instruction(0).unwrap();
        let constraint = InstructionFetchConstraint128::from_fetch(&fetch);

        // Valid fetch should give zero constraint
        let result = constraint.evaluate();
        assert_eq!(result, BinaryElem128::zero());
    }

    #[test]
    fn test_invalid_fetch_constraint() {
        let program: Vec<u8> = (0..32).collect();
        let mem = UnifiedMemory128::with_program(&program, 16).unwrap();

        let fetch = mem.fetch_instruction(0).unwrap();
        let mut constraint = InstructionFetchConstraint128::from_fetch(&fetch);

        // Tamper with the value
        constraint.word_value = BinaryElem128::from(0xdeadbeefu128);

        // Invalid fetch should give non-zero constraint
        let result = constraint.evaluate();
        assert_ne!(result, BinaryElem128::zero());
    }

    #[test]
    fn test_code_write_protection() {
        let program = vec![0u8; 32];
        let mut mem = UnifiedMemory128::with_program(&program, 16).unwrap();

        // Cannot write to code region (byte 0 is in code)
        let result = mem.write_data(0, 42);
        assert!(result.is_err(), "should not be able to write to code region");
    }

    #[test]
    #[ignore] // slow: requires large memory allocation
    fn test_code_write_protection_full() {
        let program = vec![0u8; 32];
        // Need enough memory to include HEAP_START region
        // HEAP_START = 0x100000, each word = 16 bytes
        // word index = 0x100000 / 16 = 65536, so we need at least 2^17 words
        let word_count = 1 << 17; // 131072 words
        let mut mem = UnifiedMemory128::with_program(&program, word_count).unwrap();

        // Cannot write to code region
        let result = mem.write_data(0, 42);
        assert!(result.is_err());

        // Can write to data region
        let result = mem.write_data(HEAP_START, 42);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_u32() {
        // Create a word with known u32 values
        let word: u128 = 0x44444444_33333333_22222222_11111111;
        let fetch = InstructionFetch128 {
            byte_offset: 0,
            word_index: 0,
            word_value: word,
            merkle_proof: MerkleProof128 {
                index: 0,
                value: word,
                siblings: vec![],
                root: BinaryElem128::zero(),
            },
        };

        assert_eq!(fetch.extract_u32(0), 0x11111111);
        assert_eq!(fetch.extract_u32(4), 0x22222222);
        assert_eq!(fetch.extract_u32(8), 0x33333333);
        assert_eq!(fetch.extract_u32(12), 0x44444444);
    }
}
