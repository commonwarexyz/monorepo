//! PolkaVM Trace Extraction (stub)
//! This module is only available with the `polkavm-integration` feature.

use commonware_commitment::field::{BinaryElem32, BinaryFieldElement};
use super::polkavm_adapter::PolkaVMTrace;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug)]
pub enum TraceError {
    #[cfg(feature = "polkavm-integration")]
    PolkaVMError(polkavm::Error),
    ExecutionTrapped,
    InvalidProgramBlob,
    TooManySteps(usize),
}

#[cfg(not(feature = "polkavm-integration"))]
pub fn extract_polkavm_trace(
    _program_blob: &[u8], _max_steps: usize,
) -> Result<PolkaVMTrace, TraceError> {
    panic!("PolkaVM integration not enabled. Build with --features polkavm-integration");
}

fn compute_program_hash(program_blob: &[u8]) -> BinaryElem32 {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(program_blob);
    let hash = hasher.finalize();
    let hash_u32 = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
    BinaryElem32::from(hash_u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_hash() {
        let program = b"test program";
        let hash = compute_program_hash(program);
        let hash2 = compute_program_hash(program);
        assert_eq!(hash, hash2);
        let hash3 = compute_program_hash(b"different");
        assert_ne!(hash, hash3);
    }
}
