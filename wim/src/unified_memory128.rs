//! Unified Memory Model for PolkaVM (128-bit secure version)

use crate::merkle128::{MerkleTree128, MerkleProof128};
use crate::rescue;
use commonware_commitment::field::{BinaryElem128, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub const CODE_START: u32 = 0x0000_0000;
pub const CODE_MAX_SIZE: u32 = 0x0010_0000;
pub const HEAP_START: u32 = 0x0010_0000;
#[allow(dead_code)]
pub const STACK_START: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub struct UnifiedMemory128 {
    tree: MerkleTree128,
    program_size: u32,
    word_count: usize,
}

impl UnifiedMemory128 {
    pub fn with_program(program_bytes: &[u8], word_count: usize) -> Result<Self, &'static str> {
        if !word_count.is_power_of_two() { return Err("word count must be power of 2"); }
        if program_bytes.len() as u32 > CODE_MAX_SIZE { return Err("program too large"); }

        let mut words = vec![0u128; word_count];
        for (i, chunk) in program_bytes.chunks(16).enumerate() {
            if i >= word_count { return Err("program too large for memory"); }
            let mut buf = [0u8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            words[i] = u128::from_le_bytes(buf);
        }
        let tree = MerkleTree128::new(words)?;
        Ok(Self { tree, program_size: program_bytes.len() as u32, word_count })
    }

    pub fn root(&self) -> BinaryElem128 { self.tree.root() }

    pub fn fetch_instruction(&self, byte_offset: u32) -> Result<InstructionFetch128, &'static str> {
        if byte_offset >= self.program_size { return Err("byte offset out of program bounds"); }
        let word_idx = (byte_offset / 16) as usize;
        let proof = self.tree.prove(word_idx)?;
        Ok(InstructionFetch128 {
            byte_offset, word_index: word_idx, word_value: proof.value, merkle_proof: proof,
        })
    }

    pub fn read_data(&self, byte_addr: u32) -> Result<(u128, MerkleProof128), &'static str> {
        if byte_addr < HEAP_START { return Err("data read in code region"); }
        let word_idx = (byte_addr / 16) as usize;
        if word_idx >= self.word_count { return Err("address out of bounds"); }
        let proof = self.tree.prove(word_idx)?;
        Ok((proof.value, proof))
    }

    pub fn write_data(&mut self, byte_addr: u32, value: u128) -> Result<(), &'static str> {
        if byte_addr < HEAP_START { return Err("cannot write to code region"); }
        let word_idx = (byte_addr / 16) as usize;
        if word_idx >= self.word_count { return Err("address out of bounds"); }
        self.tree.write(word_idx, value)
    }
}

#[derive(Debug, Clone)]
pub struct InstructionFetch128 {
    pub byte_offset: u32,
    pub word_index: usize,
    pub word_value: u128,
    pub merkle_proof: MerkleProof128,
}

impl InstructionFetch128 {
    pub fn verify(&self, expected_root: BinaryElem128) -> bool {
        self.merkle_proof.root == expected_root && self.merkle_proof.verify()
    }
    pub fn extract_u32(&self, byte_within_word: u32) -> u32 {
        let shift = (byte_within_word % 16) * 8;
        ((self.word_value >> shift) & 0xFFFFFFFF) as u32
    }
}

#[derive(Debug, Clone)]
pub struct InstructionFetchConstraint128 {
    pub word_index: usize,
    pub word_value: BinaryElem128,
    pub siblings: Vec<BinaryElem128>,
    pub expected_root: BinaryElem128,
}

impl InstructionFetchConstraint128 {
    pub fn from_fetch(fetch: &InstructionFetch128) -> Self {
        Self {
            word_index: fetch.word_index,
            word_value: BinaryElem128::from(fetch.word_value),
            siblings: fetch.merkle_proof.siblings.clone(),
            expected_root: fetch.merkle_proof.root,
        }
    }

    pub fn evaluate(&self) -> BinaryElem128 {
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
        current.add(&self.expected_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_memory() {
        let program = vec![0u8; 64];
        let mem = UnifiedMemory128::with_program(&program, 16).unwrap();
        assert_ne!(mem.root(), BinaryElem128::zero());
    }

    #[test]
    fn test_fetch_instruction() {
        let program: Vec<u8> = (0..32).collect();
        let mem = UnifiedMemory128::with_program(&program, 16).unwrap();
        let root = mem.root();
        let fetch = mem.fetch_instruction(0).unwrap();
        assert!(fetch.verify(root));
    }

    #[test]
    fn test_fetch_constraint() {
        let program: Vec<u8> = (0..32).collect();
        let mem = UnifiedMemory128::with_program(&program, 16).unwrap();
        let fetch = mem.fetch_instruction(0).unwrap();
        let constraint = InstructionFetchConstraint128::from_fetch(&fetch);
        assert_eq!(constraint.evaluate(), BinaryElem128::zero());
    }
}
