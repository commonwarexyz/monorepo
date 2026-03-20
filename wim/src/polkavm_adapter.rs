//! PolkaVM Integration Adapter
//!
//! This module provides integration between PolkaVM execution and Ligerito proving.
//! It extracts execution traces from PolkaVM and converts them to polynomials for proving.

use commonware_commitment::field::{BinaryElem32, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// PolkaVM register layout (13 registers)
/// Matches polkavm_common::program::Reg
#[derive(Debug, Clone, Copy)]
pub struct PolkaVMRegisters {
    pub ra: u32,  // Return address (Reg 0)
    pub sp: u32,  // Stack pointer (Reg 1)
    pub t0: u32,  // Temporary 0 (Reg 2)
    pub t1: u32,  // Temporary 1 (Reg 3)
    pub t2: u32,  // Temporary 2 (Reg 4)
    pub s0: u32,  // Saved 0 (Reg 5)
    pub s1: u32,  // Saved 1 (Reg 6)
    pub a0: u32,  // Argument 0 (Reg 7)
    pub a1: u32,  // Argument 1 (Reg 8)
    pub a2: u32,  // Argument 2 (Reg 9)
    pub a3: u32,  // Argument 3 (Reg 10)
    pub a4: u32,  // Argument 4 (Reg 11)
    pub a5: u32,  // Argument 5 (Reg 12)
}

impl PolkaVMRegisters {
    pub fn new() -> Self {
        Self {
            ra: 0, sp: 0,
            t0: 0, t1: 0, t2: 0,
            s0: 0, s1: 0,
            a0: 0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0,
        }
    }

    /// Convert to array format (for compatibility with our trace format)
    pub fn to_array(&self) -> [u32; 13] {
        [
            self.ra, self.sp,
            self.t0, self.t1, self.t2,
            self.s0, self.s1,
            self.a0, self.a1, self.a2, self.a3, self.a4, self.a5,
        ]
    }

    /// Create from array
    pub fn from_array(arr: [u32; 13]) -> Self {
        Self {
            ra: arr[0], sp: arr[1],
            t0: arr[2], t1: arr[3], t2: arr[4],
            s0: arr[5], s1: arr[6],
            a0: arr[7], a1: arr[8], a2: arr[9],
            a3: arr[10], a4: arr[11], a5: arr[12],
        }
    }
}

impl Default for PolkaVMRegisters {
    fn default() -> Self {
        Self::new()
    }
}

/// PolkaVM segmented memory model
#[derive(Debug, Clone)]
pub struct PolkaVMMemoryModel {
    /// Read-only data segment
    pub ro_data: Vec<u8>,
    /// Read-write data segment
    pub rw_data: Vec<u8>,
    /// Stack segment
    pub stack: Vec<u8>,
    /// Auxiliary data (optional)
    pub aux: Vec<u8>,

    /// Base addresses for each segment
    pub ro_base: u32,
    pub rw_base: u32,
    pub stack_base: u32,
    pub aux_base: u32,

    /// Segment sizes
    pub ro_size: u32,
    pub rw_size: u32,
    pub stack_size: u32,
    pub aux_size: u32,
}

impl PolkaVMMemoryModel {
    /// Create a new memory model from PolkaVM segments
    pub fn new(
        ro_data: Vec<u8>,
        rw_data: Vec<u8>,
        stack: Vec<u8>,
        aux: Vec<u8>,
        ro_base: u32,
        rw_base: u32,
        stack_base: u32,
        aux_base: u32,
    ) -> Self {
        Self {
            ro_size: ro_data.len() as u32,
            rw_size: rw_data.len() as u32,
            stack_size: stack.len() as u32,
            aux_size: aux.len() as u32,
            ro_data,
            rw_data,
            stack,
            aux,
            ro_base,
            rw_base,
            stack_base,
            aux_base,
        }
    }

    /// Determine which segment an address belongs to
    pub fn segment_for_address(&self, addr: u32) -> Option<MemorySegment> {
        if addr >= self.ro_base && addr < self.ro_base + self.ro_size {
            Some(MemorySegment::ReadOnly)
        } else if addr >= self.rw_base && addr < self.rw_base + self.rw_size {
            Some(MemorySegment::ReadWrite)
        } else if addr >= self.stack_base && addr < self.stack_base + self.stack_size {
            Some(MemorySegment::Stack)
        } else if self.aux_size > 0 && addr >= self.aux_base && addr < self.aux_base + self.aux_size {
            Some(MemorySegment::Auxiliary)
        } else {
            None
        }
    }

    /// Read u32 from memory (with segment routing)
    pub fn read_u32(&self, addr: u32) -> Option<u32> {
        let segment = self.segment_for_address(addr)?;
        let offset = match segment {
            MemorySegment::ReadOnly => (addr - self.ro_base) as usize,
            MemorySegment::ReadWrite => (addr - self.rw_base) as usize,
            MemorySegment::Stack => (addr - self.stack_base) as usize,
            MemorySegment::Auxiliary => (addr - self.aux_base) as usize,
        };

        let data = match segment {
            MemorySegment::ReadOnly => &self.ro_data,
            MemorySegment::ReadWrite => &self.rw_data,
            MemorySegment::Stack => &self.stack,
            MemorySegment::Auxiliary => &self.aux,
        };

        if offset + 4 <= data.len() {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }

    /// Read u8 from memory
    pub fn read_u8(&self, addr: u32) -> Option<u8> {
        let segment = self.segment_for_address(addr)?;
        let offset = match segment {
            MemorySegment::ReadOnly => (addr - self.ro_base) as usize,
            MemorySegment::ReadWrite => (addr - self.rw_base) as usize,
            MemorySegment::Stack => (addr - self.stack_base) as usize,
            MemorySegment::Auxiliary => (addr - self.aux_base) as usize,
        };

        let data = match segment {
            MemorySegment::ReadOnly => &self.ro_data,
            MemorySegment::ReadWrite => &self.rw_data,
            MemorySegment::Stack => &self.stack,
            MemorySegment::Auxiliary => &self.aux,
        };

        data.get(offset).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySegment {
    ReadOnly,
    ReadWrite,
    Stack,
    Auxiliary,
}

/// A single step in PolkaVM execution trace
#[derive(Debug, Clone)]
pub struct PolkaVMStep {
    /// Program counter
    pub pc: u32,

    /// Registers BEFORE instruction execution
    pub regs_before: PolkaVMRegisters,

    /// Registers AFTER instruction execution
    pub regs_after: PolkaVMRegisters,

    /// Instruction opcode (simplified for now)
    pub opcode: u8,

    /// Instruction operands (up to 3)
    pub operands: [u32; 3],

    /// Memory access (if any)
    pub memory_access: Option<MemoryAccess>,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryAccess {
    pub address: u32,
    pub value: u32,
    pub is_write: bool,
    pub size: MemoryAccessSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAccessSize {
    Byte,
    HalfWord,
    Word,
    DoubleWord,
}

/// Full execution trace from PolkaVM
#[derive(Debug, Clone)]
pub struct PolkaVMTrace {
    pub steps: Vec<PolkaVMStep>,
    pub initial_memory: PolkaVMMemoryModel,
    pub program_hash: BinaryElem32,
}

/// NOTE: Actual PolkaVM integration will be added when we add polkavm as a dependency
/// For now, this provides the types and structure for integration

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_array_conversion() {
        let regs = PolkaVMRegisters {
            ra: 1, sp: 2,
            t0: 3, t1: 4, t2: 5,
            s0: 6, s1: 7,
            a0: 8, a1: 9, a2: 10, a3: 11, a4: 12, a5: 13,
        };

        let arr = regs.to_array();
        assert_eq!(arr[0], 1);  // ra
        assert_eq!(arr[1], 2);  // sp
        assert_eq!(arr[7], 8);  // a0
        assert_eq!(arr[12], 13); // a5

        let regs2 = PolkaVMRegisters::from_array(arr);
        assert_eq!(regs2.ra, regs.ra);
        assert_eq!(regs2.a5, regs.a5);
    }

    #[test]
    fn test_memory_segment_routing() {
        let memory = PolkaVMMemoryModel::new(
            vec![1, 2, 3, 4],  // ro_data
            vec![5, 6, 7, 8],  // rw_data
            vec![9, 10, 11, 12], // stack
            vec![],            // aux
            0x10000,  // ro_base
            0x30000,  // rw_base
            0xfffdc000, // stack_base
            0,        // aux_base
        );

        // Test segment detection
        assert_eq!(memory.segment_for_address(0x10000), Some(MemorySegment::ReadOnly));
        assert_eq!(memory.segment_for_address(0x30000), Some(MemorySegment::ReadWrite));
        assert_eq!(memory.segment_for_address(0xfffdc000), Some(MemorySegment::Stack));
        assert_eq!(memory.segment_for_address(0x50000), None); // Out of bounds
    }

    #[test]
    fn test_memory_read() {
        let memory = PolkaVMMemoryModel::new(
            vec![0x01, 0x02, 0x03, 0x04],  // ro_data (u32 = 0x04030201)
            vec![],
            vec![],
            vec![],
            0x10000,
            0x30000,
            0xfffdc000,
            0,
        );

        let value = memory.read_u32(0x10000).unwrap();
        assert_eq!(value, 0x04030201); // Little-endian

        let byte = memory.read_u8(0x10000).unwrap();
        assert_eq!(byte, 0x01);
    }
}
