//! PolkaVM Integration Adapter
//! This module is only available with the `polkavm-integration` feature.

use commonware_commitment::field::{BinaryElem32, BinaryFieldElement};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, Default)]
pub struct PolkaVMRegisters {
    pub ra: u32, pub sp: u32,
    pub t0: u32, pub t1: u32, pub t2: u32,
    pub s0: u32, pub s1: u32,
    pub a0: u32, pub a1: u32, pub a2: u32, pub a3: u32, pub a4: u32, pub a5: u32,
}

impl PolkaVMRegisters {
    pub fn new() -> Self { Self::default() }

    pub fn to_array(&self) -> [u32; 13] {
        [self.ra, self.sp, self.t0, self.t1, self.t2,
         self.s0, self.s1, self.a0, self.a1, self.a2, self.a3, self.a4, self.a5]
    }

    pub fn from_array(arr: [u32; 13]) -> Self {
        Self {
            ra: arr[0], sp: arr[1], t0: arr[2], t1: arr[3], t2: arr[4],
            s0: arr[5], s1: arr[6], a0: arr[7], a1: arr[8], a2: arr[9],
            a3: arr[10], a4: arr[11], a5: arr[12],
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolkaVMMemoryModel {
    pub ro_data: Vec<u8>, pub rw_data: Vec<u8>,
    pub stack: Vec<u8>, pub aux: Vec<u8>,
    pub ro_base: u32, pub rw_base: u32, pub stack_base: u32, pub aux_base: u32,
    pub ro_size: u32, pub rw_size: u32, pub stack_size: u32, pub aux_size: u32,
}

impl PolkaVMMemoryModel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ro_data: Vec<u8>, rw_data: Vec<u8>, stack: Vec<u8>, aux: Vec<u8>,
        ro_base: u32, rw_base: u32, stack_base: u32, aux_base: u32,
    ) -> Self {
        Self {
            ro_size: ro_data.len() as u32, rw_size: rw_data.len() as u32,
            stack_size: stack.len() as u32, aux_size: aux.len() as u32,
            ro_data, rw_data, stack, aux,
            ro_base, rw_base, stack_base, aux_base,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAccessSize { Byte, HalfWord, Word, DoubleWord }

#[derive(Debug, Clone, Copy)]
pub struct MemoryAccess {
    pub address: u32, pub value: u32, pub is_write: bool, pub size: MemoryAccessSize,
}

#[derive(Debug, Clone)]
pub struct PolkaVMStep {
    pub pc: u32,
    pub regs_before: PolkaVMRegisters,
    pub regs_after: PolkaVMRegisters,
    pub opcode: u8,
    pub operands: [u32; 3],
    pub memory_access: Option<MemoryAccess>,
}

#[derive(Debug, Clone)]
pub struct PolkaVMTrace {
    pub steps: Vec<PolkaVMStep>,
    pub initial_memory: PolkaVMMemoryModel,
    pub program_hash: BinaryElem32,
}
