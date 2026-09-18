use super::{
    super::{DIGEST_LENGTH, Digest, IV},
    POSITION_LEN,
};

/// Wrapper that aligns the round-constant table for aligned vector loads.
#[repr(align(16))]
struct Align16<T>(T);

/// The SHA-256 round constants (FIPS 180-4, section 4.2.2).
static K: Align16<[u32; 64]> = Align16([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/// Hash two MMR node-shaped messages (`position || left || right`, 72 bytes)
/// with interleaved SHA2 instructions: one full block plus a fixed-layout
/// padding block each.
///
/// Each message is given as its constituent parts (position, left digest,
/// right digest) and loaded directly into vector registers, without first
/// concatenating them into a scratch buffer.
///
/// # Safety
///
/// The `sha2` target feature must be available.
#[allow(asm_sub_register)]
#[target_feature(enable = "sha2")]
pub unsafe fn hash_pair_72(
    left_pos: &[u8; POSITION_LEN],
    left_left: &[u8; DIGEST_LENGTH],
    left_right: &[u8; DIGEST_LENGTH],
    right_pos: &[u8; POSITION_LEN],
    right_left: &[u8; DIGEST_LENGTH],
    right_right: &[u8; DIGEST_LENGTH],
) -> (Digest, Digest) {
    let mut left_digest = [0u8; DIGEST_LENGTH];
    let mut right_digest = [0u8; DIGEST_LENGTH];
    // SAFETY: The inputs and outputs are properly sized buffers, the caller
    // guarantees the SHA2 instructions are available, and all registers
    // written by the asm are listed as outputs.
    unsafe {
        core::arch::asm!(
            include_str!("sha256_pair_block1_72.asm"),
            include_str!("sha256_rounds_2x.asm"),
            include_str!("sha256_pair_chain.asm"),
            include_str!("sha256_pair_tail8.asm"),
            include_str!("sha256_rounds_2x.asm"),
            include_str!("sha256_pair_finish.asm"),
            left_pos = in(reg) left_pos.as_ptr(),
            left_left = inout(reg) left_left.as_ptr() => _,
            left_right = inout(reg) left_right.as_ptr() => _,
            right_pos = in(reg) right_pos.as_ptr(),
            right_left = inout(reg) right_left.as_ptr() => _,
            right_right = inout(reg) right_right.as_ptr() => _,
            left_output = in(reg) left_digest.as_mut_ptr(),
            right_output = in(reg) right_digest.as_mut_ptr(),
            tmp = out(reg) _,
            k = out(reg) _,
            k_start = in(reg) K.0.as_ptr(),
            state = in(reg) IV.as_ptr(),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack)
        );
    }
    (Digest(left_digest), Digest(right_digest))
}

/// Hash two BMT node-shaped messages (`left || right`, 64 bytes) with
/// interleaved SHA2 instructions: one full block plus a compile-time
/// constant padding block each.
///
/// Each message is given as its two constituent digests and loaded directly
/// into vector registers, without first concatenating them into a scratch
/// buffer.
///
/// # Safety
///
/// The `sha2` target feature must be available.
#[allow(asm_sub_register)]
#[target_feature(enable = "sha2")]
pub unsafe fn hash_pair_64(
    left_a: &[u8; DIGEST_LENGTH],
    left_b: &[u8; DIGEST_LENGTH],
    right_a: &[u8; DIGEST_LENGTH],
    right_b: &[u8; DIGEST_LENGTH],
) -> (Digest, Digest) {
    let mut left_digest = [0u8; DIGEST_LENGTH];
    let mut right_digest = [0u8; DIGEST_LENGTH];
    // SAFETY: The inputs and outputs are properly sized buffers, the caller
    // guarantees the SHA2 instructions are available, and all registers
    // written by the asm are listed as outputs.
    unsafe {
        core::arch::asm!(
            include_str!("sha256_pair_block1_64.asm"),
            include_str!("sha256_rounds_2x.asm"),
            include_str!("sha256_pair_chain.asm"),
            include_str!("sha256_pair_tail0.asm"),
            include_str!("sha256_rounds_2x.asm"),
            include_str!("sha256_pair_finish.asm"),
            left_a = in(reg) left_a.as_ptr(),
            left_b = in(reg) left_b.as_ptr(),
            right_a = in(reg) right_a.as_ptr(),
            right_b = in(reg) right_b.as_ptr(),
            left_output = in(reg) left_digest.as_mut_ptr(),
            right_output = in(reg) right_digest.as_mut_ptr(),
            tmp = out(reg) _,
            k = out(reg) _,
            k_start = in(reg) K.0.as_ptr(),
            state = in(reg) IV.as_ptr(),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack)
        );
    }
    (Digest(left_digest), Digest(right_digest))
}
