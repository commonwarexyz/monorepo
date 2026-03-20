//! PolkaVM Trace Extraction
//!
//! This module implements trace extraction from PolkaVM execution.
//! It hooks into PolkaVM's step_tracing mode to capture execution traces
//! that can be proven with Ligerito.
//!
//! ## Host Call Handling
//!
//! The tracer accepts a `HostCallHandler` trait object that provides
//! the actual implementation of host functions (network I/O, etc.).
//! This allows the same tracer to be used with different host environments.

#[cfg(feature = "polkavm-integration")]
use polkavm::{Engine, Module, RawInstance, InterruptKind, ProgramBlob, ProgramCounter, Reg, ModuleConfig};
#[cfg(feature = "polkavm-integration")]
use polkavm::program::{Instruction, Opcode};

use commonware_commitment::field::{BinaryElem32, BinaryFieldElement};
use super::polkavm_adapter::{PolkaVMRegisters, PolkaVMMemoryModel, PolkaVMStep, PolkaVMTrace, MemoryAccess, MemoryAccessSize};
use super::host_calls::{HostCallHandler, HostCallTrace, DummyHostHandler};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Error type for trace extraction
#[derive(Debug)]
pub enum TraceError {
    #[cfg(feature = "polkavm-integration")]
    PolkaVMError(polkavm::Error),
    ExecutionTrapped,
    InvalidProgramBlob,
    TooManySteps(usize),
}

#[cfg(feature = "polkavm-integration")]
impl From<polkavm::Error> for TraceError {
    fn from(e: polkavm::Error) -> Self {
        TraceError::PolkaVMError(e)
    }
}

/// Extended trace result including host call trace
#[derive(Debug)]
pub struct ExtendedTrace {
    /// PolkaVM execution trace
    pub execution_trace: PolkaVMTrace,
    /// Host call trace (for proof generation)
    pub host_trace: HostCallTrace,
}

/// Extract execution trace from PolkaVM program with custom host handler
///
/// # Arguments
/// - `program_blob`: Compiled PolkaVM program (.polkavm binary)
/// - `max_steps`: Maximum number of execution steps (prevents infinite loops)
/// - `host_handler`: Handler for host function calls (network I/O, etc.)
///
/// # Returns
/// Full execution trace including register states, memory accesses, and host calls
#[cfg(feature = "polkavm-integration")]
pub fn extract_polkavm_trace_with_host<H: HostCallHandler>(
    program_blob: &[u8],
    max_steps: usize,
    host_handler: &H,
) -> Result<ExtendedTrace, TraceError> {
    let execution_trace = extract_polkavm_trace_inner(program_blob, max_steps, Some(host_handler))?;
    let host_trace = host_handler.get_trace();
    Ok(ExtendedTrace {
        execution_trace,
        host_trace,
    })
}

/// Extract execution trace from PolkaVM program (backward compatible)
///
/// # Arguments
/// - `program_blob`: Compiled PolkaVM program (.polkavm binary)
/// - `max_steps`: Maximum number of execution steps (prevents infinite loops)
///
/// # Returns
/// Full execution trace including all register states and memory accesses
#[cfg(feature = "polkavm-integration")]
pub fn extract_polkavm_trace(
    program_blob: &[u8],
    max_steps: usize,
) -> Result<PolkaVMTrace, TraceError> {
    let dummy = DummyHostHandler::new();
    extract_polkavm_trace_inner(program_blob, max_steps, Some(&dummy))
}

/// Internal trace extraction with optional host handler
#[cfg(feature = "polkavm-integration")]
fn extract_polkavm_trace_inner<H: HostCallHandler>(
    program_blob: &[u8],
    max_steps: usize,
    host_handler: Option<&H>,
) -> Result<PolkaVMTrace, TraceError> {
    // 1. Create configuration with step tracing enabled
    let mut config = ModuleConfig::default();
    config.set_step_tracing(true);

    // 2. Load program blob
    let blob = ProgramBlob::parse(program_blob.into())
        .map_err(|_| TraceError::InvalidProgramBlob)?;

    // 3. Create engine and module
    let engine = Engine::new(&Default::default())?;
    let module = Module::from_blob(&engine, &config, blob.clone())?;

    // 4. Capture initial memory state (before instantiation)
    let initial_memory = capture_memory_state(&blob, &module);

    // 5. Create raw instance and initialize
    let mut instance = module.instantiate()?;

    // Set up entry point (find first export or use default)
    if let Some(export) = module.exports().next() {
        let entry_pc = export.program_counter();
        #[cfg(feature = "std")]
        eprintln!("Found export at PC={:#x}", entry_pc.0);

        instance.set_next_program_counter(entry_pc);
        instance.set_reg(Reg::RA, polkavm::RETURN_TO_HOST);
        instance.set_reg(Reg::SP, module.default_sp());
        // Set up arguments for the function (if needed)
        instance.set_reg(Reg::A0, 1);
        instance.set_reg(Reg::A1, 10);

        #[cfg(feature = "std")]
        eprintln!("Initialized: PC should be set, RA={:#x}, SP={:#x}",
                 polkavm::RETURN_TO_HOST, module.default_sp());
    } else {
        // No exports, program might not be callable
        #[cfg(feature = "std")]
        eprintln!("Warning: No exports found in program");
    }

    // 6. Execute and collect trace
    let mut steps = Vec::new();
    let mut step_count = 0;

    loop {
        if step_count >= max_steps {
            return Err(TraceError::TooManySteps(max_steps));
        }

        // Capture state BEFORE step (must happen AFTER first run() for PC to be valid)
        let pc = match instance.program_counter() {
            Some(pc) => pc,
            None if step_count == 0 => {
                // PC not set yet on first iteration, this is OK - run() will set it
                #[cfg(feature = "std")]
                eprintln!("PC not set before first run, this is expected");

                // Do first run to initialize PC
                match instance.run()? {
                    InterruptKind::Step => {},
                    InterruptKind::Finished => break,
                    InterruptKind::Trap => return Err(TraceError::ExecutionTrapped),
                    InterruptKind::Ecalli(hostcall_num) => {
                        if let Some(handler) = host_handler {
                            let a0 = instance.reg(Reg::A0) as u32;
                            let a1 = instance.reg(Reg::A1) as u32;
                            let a2 = instance.reg(Reg::A2) as u32;
                            let a3 = instance.reg(Reg::A3) as u32;
                            let a4 = instance.reg(Reg::A4) as u32;
                            let a5 = instance.reg(Reg::A5) as u32;
                            let mut memory = vec![0u8; 64 * 1024];
                            let (result, _) = handler.handle_call(
                                hostcall_num, &mut memory,
                                a0, a1, a2, a3, a4, a5,
                            );
                            instance.set_reg(Reg::A0, result as u64);
                        } else {
                            instance.set_reg(Reg::A0, 100);
                        }
                    }
                    _ => {}
                }
                continue; // Skip to next iteration with valid PC
            }
            None => {
                #[cfg(feature = "std")]
                eprintln!("Program counter is None at step {}", step_count);
                return Err(TraceError::ExecutionTrapped);
            }
        };

        let regs_before = capture_registers(&instance);

        // Execute one step
        match instance.run()? {
            InterruptKind::Step => {
                // Capture state AFTER step
                let regs_after = capture_registers(&instance);

                // Get the instruction that was executed
                let instruction = get_instruction_at_pc(&blob, pc)?;

                // Capture memory access (if any)
                let memory_access = detect_memory_access(&instruction, &regs_before);

                steps.push(PolkaVMStep {
                    pc: pc.0,  // ProgramCounter wraps a u32
                    regs_before,
                    regs_after,
                    opcode: instruction_to_opcode(&instruction),
                    operands: instruction_to_operands(&instruction),
                    memory_access,
                });

                step_count += 1;
            }
            InterruptKind::Finished => break,
            InterruptKind::Trap => return Err(TraceError::ExecutionTrapped),
            InterruptKind::Ecalli(hostcall_num) => {
                // External call - dispatch to host handler
                if let Some(handler) = host_handler {
                    // Get register arguments
                    let a0 = instance.reg(Reg::A0) as u32;
                    let a1 = instance.reg(Reg::A1) as u32;
                    let a2 = instance.reg(Reg::A2) as u32;
                    let a3 = instance.reg(Reg::A3) as u32;
                    let a4 = instance.reg(Reg::A4) as u32;
                    let a5 = instance.reg(Reg::A5) as u32;

                    // Get memory slice for host call
                    // Note: In production, we'd need proper memory access
                    let mut memory = vec![0u8; 64 * 1024]; // 64KB guest memory

                    // Call host handler
                    let (result, _record) = handler.handle_call(
                        hostcall_num,
                        &mut memory,
                        a0, a1, a2, a3, a4, a5,
                    );

                    // Set return value
                    instance.set_reg(Reg::A0, result as u64);
                } else {
                    // No handler - return dummy value
                    instance.set_reg(Reg::A0, 100);
                }
                // Continue execution
                step_count += 1;
            }
            _ => {}
        }
    }

    // 7. Compute program hash
    let program_hash = compute_program_hash(program_blob);

    Ok(PolkaVMTrace {
        steps,
        initial_memory,
        program_hash,
    })
}

/// Capture all 13 registers from PolkaVM instance
#[cfg(feature = "polkavm-integration")]
fn capture_registers(instance: &RawInstance) -> PolkaVMRegisters {
    PolkaVMRegisters {
        ra: instance.reg(Reg::RA) as u32,
        sp: instance.reg(Reg::SP) as u32,
        t0: instance.reg(Reg::T0) as u32,
        t1: instance.reg(Reg::T1) as u32,
        t2: instance.reg(Reg::T2) as u32,
        s0: instance.reg(Reg::S0) as u32,
        s1: instance.reg(Reg::S1) as u32,
        a0: instance.reg(Reg::A0) as u32,
        a1: instance.reg(Reg::A1) as u32,
        a2: instance.reg(Reg::A2) as u32,
        a3: instance.reg(Reg::A3) as u32,
        a4: instance.reg(Reg::A4) as u32,
        a5: instance.reg(Reg::A5) as u32,
    }
}

/// Capture memory state from PolkaVM program blob and module
#[cfg(feature = "polkavm-integration")]
fn capture_memory_state(blob: &ProgramBlob, module: &Module) -> PolkaVMMemoryModel {
    // Extract segment data from the program blob
    let ro_data = blob.ro_data().to_vec();
    let rw_data = blob.rw_data().to_vec();

    // Stack and aux segments start empty
    let stack = Vec::new();
    let aux = Vec::new();

    // Get base addresses from module's memory map
    let memory_map = module.memory_map();
    let ro_base = memory_map.ro_data_range().start;
    let rw_base = memory_map.rw_data_range().start;
    let stack_base = memory_map.stack_address_low();
    let aux_base = 0; // No aux data by default

    PolkaVMMemoryModel::new(
        ro_data,
        rw_data,
        stack,
        aux,
        ro_base,
        rw_base,
        stack_base,
        aux_base,
    )
}

/// Get the instruction at a specific program counter
#[cfg(feature = "polkavm-integration")]
fn get_instruction_at_pc(blob: &ProgramBlob, pc: ProgramCounter) -> Result<Instruction, TraceError> {
    // Get instructions at the given PC
    let mut instructions = blob.instructions_bounded_at(pc);

    // Get the first (and only) instruction at this PC
    match instructions.next() {
        Some(parsed) => Ok(parsed.kind),
        None => Err(TraceError::ExecutionTrapped), // PC out of bounds
    }
}

/// Detect if an instruction performs a memory access
#[cfg(feature = "polkavm-integration")]
fn detect_memory_access(instruction: &Instruction, regs: &PolkaVMRegisters) -> Option<MemoryAccess> {
    use polkavm::program::Instruction::*;

    // We'll use a visitor pattern to extract memory access info
    // For now, match on common load/store instructions
    match instruction {
        // Load instructions - read from memory
        load_indirect_u8(dst, base, offset) |
        load_indirect_i8(dst, base, offset) => {
            let regs_arr = regs.to_array();
            let base_reg = base.get() as usize;
            let base_val = regs_arr[base_reg];
            let address = base_val.wrapping_add(*offset);
            Some(MemoryAccess {
                address,
                value: 0, // We don't know the value before execution
                is_write: false,
                size: MemoryAccessSize::Byte,
            })
        }

        load_indirect_u16(dst, base, offset) |
        load_indirect_i16(dst, base, offset) => {
            let regs_arr = regs.to_array();
            let base_reg = base.get() as usize;
            let base_val = regs_arr[base_reg];
            let address = base_val.wrapping_add(*offset);
            Some(MemoryAccess {
                address,
                value: 0,
                is_write: false,
                size: MemoryAccessSize::HalfWord,
            })
        }

        load_indirect_u32(dst, base, offset) |
        load_indirect_i32(dst, base, offset) => {
            let regs_arr = regs.to_array();
            let base_reg = base.get() as usize;
            let base_val = regs_arr[base_reg];
            let address = base_val.wrapping_add(*offset);
            Some(MemoryAccess {
                address,
                value: 0,
                is_write: false,
                size: MemoryAccessSize::Word,
            })
        }

        // Store instructions - write to memory
        store_indirect_u8(src, base, offset) => {
            let regs_arr = regs.to_array();
            let base_reg = base.get() as usize;
            let src_reg = src.get() as usize;
            let base_val = regs_arr[base_reg];
            let address = base_val.wrapping_add(*offset);
            let value = regs_arr[src_reg];
            Some(MemoryAccess {
                address,
                value,
                is_write: true,
                size: MemoryAccessSize::Byte,
            })
        }

        store_indirect_u16(src, base, offset) => {
            let regs_arr = regs.to_array();
            let base_reg = base.get() as usize;
            let src_reg = src.get() as usize;
            let base_val = regs_arr[base_reg];
            let address = base_val.wrapping_add(*offset);
            let value = regs_arr[src_reg];
            Some(MemoryAccess {
                address,
                value,
                is_write: true,
                size: MemoryAccessSize::HalfWord,
            })
        }

        store_indirect_u32(src, base, offset) => {
            let regs_arr = regs.to_array();
            let base_reg = base.get() as usize;
            let src_reg = src.get() as usize;
            let base_val = regs_arr[base_reg];
            let address = base_val.wrapping_add(*offset);
            let value = regs_arr[src_reg];
            Some(MemoryAccess {
                address,
                value,
                is_write: true,
                size: MemoryAccessSize::Word,
            })
        }

        // No memory access for other instructions
        _ => None,
    }
}

/// Visitor to extract opcode from instruction
#[cfg(feature = "polkavm-integration")]
struct OpcodeExtractor {
    opcode: u8,
}

#[cfg(feature = "polkavm-integration")]
impl OpcodeExtractor {
    fn new() -> Self {
        Self { opcode: 0xFF }
    }
}

// We need to implement InstructionVisitor, but it's defined via macro in polkavm-common.
// For now, we'll use the Opcode enum instead which gives us a stable u8 value.
// This is simpler and more maintainable than implementing the full visitor.

/// Convert PolkaVM instruction to simplified opcode byte
#[cfg(feature = "polkavm-integration")]
fn instruction_to_opcode(_instruction: &Instruction) -> u8 {
    // TODO: In newer polkavm, Opcode is not directly castable to u8.
    // The actual constraint checking uses pattern matching on Instruction variants,
    // not the raw opcode byte. This field is for trace inspection only.
    // For now, return 0 as placeholder - proper fix needed for polkavm 0.30+
    0
}

/// Visitor to extract operands from instruction
#[cfg(feature = "polkavm-integration")]
struct OperandExtractor {
    operands: [u32; 3],
}

#[cfg(feature = "polkavm-integration")]
impl OperandExtractor {
    fn new() -> Self {
        Self { operands: [0, 0, 0] }
    }

    fn extract(instruction: &Instruction) -> [u32; 3] {
        use polkavm::program::Instruction::*;

        // Extract operands based on instruction type
        // Format: [dst/src1, src2/base, imm/offset]
        match instruction {
            // Argless instructions
            trap | fallthrough => [0, 0, 0],

            // reg_imm instructions
            load_imm(reg, imm) => [reg.get() as u32, 0, *imm],

            // reg_reg_imm instructions (arithmetic, shifts, etc.)
            add_imm_32(dst, src, imm) |
            and_imm(dst, src, imm) |
            xor_imm(dst, src, imm) |
            or_imm(dst, src, imm) |
            mul_imm_32(dst, src, imm) |
            set_less_than_unsigned_imm(dst, src, imm) |
            set_less_than_signed_imm(dst, src, imm) |
            shift_logical_left_imm_32(dst, src, imm) |
            shift_logical_right_imm_32(dst, src, imm) |
            shift_arithmetic_right_imm_32(dst, src, imm) |
            negate_and_add_imm_32(dst, src, imm) => {
                [dst.get() as u32, src.get() as u32, *imm]
            }

            // reg_reg_reg instructions
            add_32(dst, src1, src2) |
            sub_32(dst, src1, src2) |
            and(dst, src1, src2) |
            xor(dst, src1, src2) |
            or(dst, src1, src2) |
            mul_32(dst, src1, src2) |
            mul_upper_signed_signed(dst, src1, src2) |
            mul_upper_unsigned_unsigned(dst, src1, src2) |
            mul_upper_signed_unsigned(dst, src1, src2) |
            div_unsigned_32(dst, src1, src2) |
            div_signed_32(dst, src1, src2) |
            rem_unsigned_32(dst, src1, src2) |
            rem_signed_32(dst, src1, src2) |
            set_less_than_unsigned(dst, src1, src2) |
            set_less_than_signed(dst, src1, src2) |
            shift_logical_left_32(dst, src1, src2) |
            shift_logical_right_32(dst, src1, src2) |
            shift_arithmetic_right_32(dst, src1, src2) => {
                [dst.get() as u32, src1.get() as u32, src2.get() as u32]
            }

            // Load indirect (dst, base, offset)
            load_indirect_u8(dst, base, offset) |
            load_indirect_i8(dst, base, offset) |
            load_indirect_u16(dst, base, offset) |
            load_indirect_i16(dst, base, offset) |
            load_indirect_u32(dst, base, offset) |
            load_indirect_i32(dst, base, offset) => {
                [dst.get() as u32, base.get() as u32, *offset]
            }

            // Store indirect (src, base, offset)
            store_indirect_u8(src, base, offset) |
            store_indirect_u16(src, base, offset) |
            store_indirect_u32(src, base, offset) => {
                [src.get() as u32, base.get() as u32, *offset]
            }

            // Branches (reg, imm, offset)
            branch_eq_imm(reg, imm, offset) |
            branch_not_eq_imm(reg, imm, offset) |
            branch_less_unsigned_imm(reg, imm, offset) |
            branch_less_signed_imm(reg, imm, offset) |
            branch_greater_or_equal_unsigned_imm(reg, imm, offset) |
            branch_greater_or_equal_signed_imm(reg, imm, offset) => {
                [reg.get() as u32, *imm, *offset]
            }

            // Branches (reg, reg, offset)
            branch_eq(reg1, reg2, offset) |
            branch_not_eq(reg1, reg2, offset) |
            branch_less_unsigned(reg1, reg2, offset) |
            branch_less_signed(reg1, reg2, offset) |
            branch_greater_or_equal_unsigned(reg1, reg2, offset) |
            branch_greater_or_equal_signed(reg1, reg2, offset) => {
                [reg1.get() as u32, reg2.get() as u32, *offset]
            }

            // Jump instructions
            jump(offset) => [0, 0, *offset],
            jump_indirect(base, offset) => [0, base.get() as u32, *offset],

            // Move
            move_reg(dst, src) => [dst.get() as u32, src.get() as u32, 0],

            // Cmov (conditional move)
            cmov_if_zero(dst, src, cond) |
            cmov_if_not_zero(dst, src, cond) => {
                [dst.get() as u32, src.get() as u32, cond.get() as u32]
            }

            // For all other instructions, return zeros
            // This includes ecalli, load_imm_and_jump, etc.
            _ => [0, 0, 0],
        }
    }
}

/// Convert PolkaVM instruction operands to array
#[cfg(feature = "polkavm-integration")]
fn instruction_to_operands(instruction: &Instruction) -> [u32; 3] {
    OperandExtractor::extract(instruction)
}

/// Compute hash of program blob for verification
fn compute_program_hash(program_blob: &[u8]) -> BinaryElem32 {
    // Use SHA256 to hash the program
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(program_blob);
    let hash = hasher.finalize();

    // Take first 4 bytes as u32
    let hash_u32 = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
    BinaryElem32::from(hash_u32)
}

#[cfg(all(test, feature = "polkavm-integration"))]
mod tests {
    use super::*;

    #[test]
    fn test_trace_extraction_placeholder() {
        // This will be a real test once we have a sample PolkaVM binary
        // For now, just ensure the module compiles
        assert!(true);
    }

    #[test]
    fn test_program_hash() {
        let program = b"test program";
        let hash = compute_program_hash(program);

        // Hash should be deterministic
        let hash2 = compute_program_hash(program);
        assert_eq!(hash, hash2);

        // Different program should have different hash
        let hash3 = compute_program_hash(b"different");
        assert_ne!(hash, hash3);
    }
}

#[cfg(not(feature = "polkavm-integration"))]
pub fn extract_polkavm_trace(
    _program_blob: &[u8],
    _max_steps: usize,
) -> Result<PolkaVMTrace, TraceError> {
    panic!("PolkaVM integration not enabled. Build with --features polkavm-integration");
}
