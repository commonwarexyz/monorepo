//! Read-only memory support for pcVM Phase 2
//!
//! This module provides immutable memory that can be read during execution.
//! No writes are supported - that's Phase 3.

use commonware_commitment::field::{BinaryElem32, BinaryFieldElement};
use super::rescue::RescueHash;
use commonware_commitment::field::BinaryElem128;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Read-only memory for pcVM
#[derive(Debug, Clone)]
pub struct ReadOnlyMemory {
    /// Memory contents (32-bit words)
    /// Address 0x0000 typically contains program code
    /// Higher addresses contain constant data
    pub data: Vec<u32>,

    /// Poseidon hash of entire memory contents
    pub hash: BinaryElem32,
}

impl ReadOnlyMemory {
    /// Create new read-only memory from data
    pub fn new(data: Vec<u32>) -> Self {
        let hash = Self::compute_hash(&data);
        Self { data, hash }
    }

    /// Create empty memory with specified size
    pub fn with_size(size: usize) -> Self {
        Self::new(vec![0; size])
    }

    /// Read a word from memory
    pub fn read(&self, address: u32) -> Option<u32> {
        self.data.get(address as usize).copied()
    }

    /// Read a word from memory (unchecked, returns 0 if out of bounds)
    pub fn read_unchecked(&self, address: u32) -> u32 {
        self.read(address).unwrap_or(0)
    }

    /// Write to memory (during setup only, before hashing)
    pub fn write(&mut self, address: u32, value: u32) -> Result<(), &'static str> {
        if (address as usize) < self.data.len() {
            self.data[address as usize] = value;
            // Recompute hash after modification
            self.hash = Self::compute_hash(&self.data);
            Ok(())
        } else {
            Err("Address out of bounds")
        }
    }

    /// Get memory size in words
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Compute hash of memory contents using Rescue-Prime
    fn compute_hash(data: &[u32]) -> BinaryElem32 {
        // Hash in chunks, lifting u32 values to u128 for Rescue-Prime
        const CHUNK_SIZE: usize = 256;

        let mut running_hash = BinaryElem128::zero();

        for chunk in data.chunks(CHUNK_SIZE) {
            let elements: Vec<BinaryElem128> = chunk.iter()
                .map(|&w| BinaryElem128::from(w as u128))
                .collect();

            let chunk_hash = RescueHash::hash_elements(&elements);
            running_hash = running_hash.add(&chunk_hash);
        }

        // Truncate 128-bit hash to 32-bit for compatibility
        BinaryElem32::from(running_hash.poly().value() as u32)
    }

    /// Load program code into memory starting at address 0
    pub fn load_program(&mut self, program_bytes: &[u32]) -> Result<(), &'static str> {
        if program_bytes.len() > self.data.len() {
            return Err("Program too large for memory");
        }

        for (i, &word) in program_bytes.iter().enumerate() {
            self.data[i] = word;
        }

        // Recompute hash
        self.hash = Self::compute_hash(&self.data);
        Ok(())
    }

    /// Verify that memory hash matches expected value
    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(&self.data);
        computed == self.hash
    }
}

/// Memory access record (for trace generation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    /// Address accessed
    pub address: u32,

    /// Value read from memory
    pub value: u32,

    /// Step index where access occurred
    pub step: usize,
}

impl MemoryAccess {
    pub fn new(address: u32, value: u32, step: usize) -> Self {
        Self { address, value, step }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_memory() {
        let mem = ReadOnlyMemory::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(mem.size(), 5);
        assert_eq!(mem.read(0), Some(1));
        assert_eq!(mem.read(4), Some(5));
        assert_eq!(mem.read(5), None);
    }

    #[test]
    fn test_memory_hash() {
        let mem1 = ReadOnlyMemory::new(vec![1, 2, 3]);
        let mem2 = ReadOnlyMemory::new(vec![1, 2, 3]);
        let mem3 = ReadOnlyMemory::new(vec![1, 2, 4]);

        // Same contents = same hash
        assert_eq!(mem1.hash, mem2.hash);

        // Different contents = different hash
        assert_ne!(mem1.hash, mem3.hash);
    }

    #[test]
    fn test_memory_write() {
        let mut mem = ReadOnlyMemory::with_size(10);
        let initial_hash = mem.hash;

        // Write updates hash
        mem.write(5, 42).unwrap();
        assert_ne!(mem.hash, initial_hash);

        // Value written correctly
        assert_eq!(mem.read(5), Some(42));

        // Hash verification
        assert!(mem.verify_hash());
    }

    #[test]
    fn test_out_of_bounds() {
        let mem = ReadOnlyMemory::with_size(10);

        // Read out of bounds returns None
        assert_eq!(mem.read(10), None);
        assert_eq!(mem.read(100), None);

        // Unchecked read returns 0
        assert_eq!(mem.read_unchecked(10), 0);
        assert_eq!(mem.read_unchecked(100), 0);
    }

    #[test]
    fn test_load_program() {
        let mut mem = ReadOnlyMemory::with_size(100);
        let program = vec![0x01, 0x02, 0x03, 0xFF]; // Example opcodes

        mem.load_program(&program).unwrap();

        assert_eq!(mem.read(0), Some(0x01));
        assert_eq!(mem.read(1), Some(0x02));
        assert_eq!(mem.read(2), Some(0x03));
        assert_eq!(mem.read(3), Some(0xFF));

        // Hash should be updated
        assert!(mem.verify_hash());
    }

    #[test]
    fn test_memory_access_record() {
        let access = MemoryAccess::new(0x1000, 42, 5);

        assert_eq!(access.address, 0x1000);
        assert_eq!(access.value, 42);
        assert_eq!(access.step, 5);
    }

    #[test]
    fn test_large_memory_hash() {
        // Test that large memory can be hashed
        let large_mem = ReadOnlyMemory::with_size(10000);
        assert!(large_mem.verify_hash());

        // Different large memories should have different hashes
        let mut mem1 = ReadOnlyMemory::with_size(10000);
        let mut mem2 = ReadOnlyMemory::with_size(10000);

        mem1.write(5000, 123).unwrap();
        mem2.write(5000, 456).unwrap();

        assert_ne!(mem1.hash, mem2.hash);
    }

    #[test]
    fn test_hash_deterministic() {
        let data = vec![1, 2, 3, 4, 5];

        let mem1 = ReadOnlyMemory::new(data.clone());
        let mem2 = ReadOnlyMemory::new(data.clone());

        // Hash should be deterministic
        assert_eq!(mem1.hash, mem2.hash);

        // Multiple recomputations should match
        let hash1 = ReadOnlyMemory::compute_hash(&data);
        let hash2 = ReadOnlyMemory::compute_hash(&data);
        assert_eq!(hash1, hash2);
    }
}
