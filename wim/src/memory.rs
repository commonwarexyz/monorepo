//! Read-only memory support for pcVM Phase 2

use commonware_commitment::field::{BinaryElem32, BinaryElem128, BinaryFieldElement};
use super::rescue::RescueHash;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct ReadOnlyMemory {
    pub data: Vec<u32>,
    pub hash: BinaryElem32,
}

impl ReadOnlyMemory {
    pub fn new(data: Vec<u32>) -> Self {
        let hash = Self::compute_hash(&data);
        Self { data, hash }
    }

    pub fn with_size(size: usize) -> Self { Self::new(vec![0; size]) }

    pub fn read(&self, address: u32) -> Option<u32> {
        self.data.get(address as usize).copied()
    }

    pub fn read_unchecked(&self, address: u32) -> u32 {
        self.read(address).unwrap_or(0)
    }

    pub fn write(&mut self, address: u32, value: u32) -> Result<(), &'static str> {
        if (address as usize) < self.data.len() {
            self.data[address as usize] = value;
            self.hash = Self::compute_hash(&self.data);
            Ok(())
        } else {
            Err("Address out of bounds")
        }
    }

    pub fn size(&self) -> usize { self.data.len() }

    fn compute_hash(data: &[u32]) -> BinaryElem32 {
        const CHUNK_SIZE: usize = 256;
        let mut running_hash = BinaryElem128::zero();
        for chunk in data.chunks(CHUNK_SIZE) {
            let elements: Vec<BinaryElem128> = chunk.iter()
                .map(|&w| BinaryElem128::from(w as u128))
                .collect();
            let chunk_hash = RescueHash::hash_elements(&elements);
            running_hash = running_hash.add(&chunk_hash);
        }
        BinaryElem32::from(running_hash.poly().value() as u32)
    }

    pub fn load_program(&mut self, program_bytes: &[u32]) -> Result<(), &'static str> {
        if program_bytes.len() > self.data.len() { return Err("Program too large for memory"); }
        for (i, &word) in program_bytes.iter().enumerate() {
            self.data[i] = word;
        }
        self.hash = Self::compute_hash(&self.data);
        Ok(())
    }

    pub fn verify_hash(&self) -> bool {
        Self::compute_hash(&self.data) == self.hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    pub address: u32,
    pub value: u32,
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
        assert_eq!(mem.read(5), None);
    }

    #[test]
    fn test_memory_hash() {
        let mem1 = ReadOnlyMemory::new(vec![1, 2, 3]);
        let mem2 = ReadOnlyMemory::new(vec![1, 2, 3]);
        let mem3 = ReadOnlyMemory::new(vec![1, 2, 4]);
        assert_eq!(mem1.hash, mem2.hash);
        assert_ne!(mem1.hash, mem3.hash);
    }

    #[test]
    fn test_verify_hash() {
        let mut mem = ReadOnlyMemory::with_size(10);
        mem.write(5, 42).unwrap();
        assert!(mem.verify_hash());
    }
}
