use super::{
    super::{BMT_NODE_LEN, MMR_NODE_LEN, POSITION_LEN},
    Align16, K,
};
use crate::sha256::{DIGEST_LENGTH, Digest, IV};

/// Shuffle mask converting between byte and word endianness.
pub(super) static BYTE_SWAP_MASK: Align16<[u8; 16]> =
    Align16([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]);

/// The `0x80` terminator following the 8-byte message tail in the MMR node's
/// padding block (message ends 8 bytes into the second block).
static FINAL_72_PAD: Align16<[u32; 4]> = Align16([0, 0, 0x80000000, 0]);

/// The message bit length in the final words of the MMR node's padding block.
static FINAL_72_LENGTH: Align16<[u32; 4]> = Align16([0, 0, 0, (MMR_NODE_LEN * 8) as u32]);

/// The SHA-256 schedule words plus round constants for the fixed padding
/// block after a 64-byte BMT node.
static FINAL_64_WK: Align16<[u32; 64]> = Align16({
    let mut schedule = [0u32; 64];
    schedule[0] = 0x80000000;
    schedule[15] = (BMT_NODE_LEN * 8) as u32;

    let mut i = 16;
    while i < schedule.len() {
        let prev15 = schedule[i - 15];
        let sigma0 = prev15.rotate_right(7) ^ prev15.rotate_right(18) ^ (prev15 >> 3);
        let prev2 = schedule[i - 2];
        let sigma1 = prev2.rotate_right(17) ^ prev2.rotate_right(19) ^ (prev2 >> 10);
        schedule[i] = schedule[i - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[i - 7])
            .wrapping_add(sigma1);
        i += 1;
    }

    let mut i = 0;
    while i < schedule.len() {
        schedule[i] = schedule[i].wrapping_add(K.0[i]);
        i += 1;
    }
    schedule
});

/// Hash two MMR node-shaped messages (`position || left || right`, 72 bytes)
/// with interleaved SHA-NI instructions: one full block plus a fixed-layout
/// padding block each.
///
/// Each message is given as its constituent parts (position, left digest,
/// right digest) and loaded directly into vector registers, without first
/// concatenating them into a scratch buffer.
///
/// # Safety
///
/// The `sha`, `avx2`, `ssse3`, and `sse4.1` target features must be available.
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
pub(in crate::sha256::simd) unsafe fn hash_pair_72(
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
    // guarantees every instruction used here is available, and all registers
    // written by the asm are listed as outputs. The asm spills to the stack
    // with aligned loads, so adding options(nostack) would be unsound.
    unsafe {
        core::arch::asm!(
            include_str!("sha256_pair_macros.asm"),
            include_str!("sha256_pair_block1_72.asm"),
            include_str!("sha256_pair_tail8.asm"),
            include_str!("sha256_pair_finish.asm"),
            left_pos = in(reg) left_pos.as_ptr(),
            left_left = in(reg) left_left.as_ptr(),
            left_right = in(reg) left_right.as_ptr(),
            right_pos = in(reg) right_pos.as_ptr(),
            right_left = in(reg) right_left.as_ptr(),
            right_right = in(reg) right_right.as_ptr(),
            left_output = in(reg) left_digest.as_mut_ptr(),
            right_output = in(reg) right_digest.as_mut_ptr(),
            state = in(reg) IV.as_ptr(),
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            pad = in(reg) FINAL_72_PAD.0.as_ptr(),
            len = in(reg) FINAL_72_LENGTH.0.as_ptr(),
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
        );
    }
    (Digest(left_digest), Digest(right_digest))
}

/// Hash two BMT node-shaped messages (`left || right`, 64 bytes) with
/// interleaved SHA-NI instructions: one full block plus a compile-time
/// constant padding block each.
///
/// Each message is given as its two constituent digests and loaded directly
/// into vector registers, without first concatenating them into a scratch
/// buffer.
///
/// # Safety
///
/// The `sha`, `avx2`, `ssse3`, and `sse4.1` target features must be available.
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
pub(in crate::sha256::simd) unsafe fn hash_pair_64(
    left_a: &[u8; DIGEST_LENGTH],
    left_b: &[u8; DIGEST_LENGTH],
    right_a: &[u8; DIGEST_LENGTH],
    right_b: &[u8; DIGEST_LENGTH],
) -> (Digest, Digest) {
    let mut left_digest = [0u8; DIGEST_LENGTH];
    let mut right_digest = [0u8; DIGEST_LENGTH];
    // SAFETY: The inputs and outputs are properly sized buffers, the caller
    // guarantees every instruction used here is available, and all registers
    // written by the asm are listed as outputs. The chaining states remain in
    // vector registers, the fixed schedule table is 16-byte aligned with every
    // load in bounds, and the asm does not use the stack.
    unsafe {
        core::arch::asm!(
            include_str!("sha256_pair_macros.asm"),
            include_str!("sha256_pair_block1_64.asm"),
            include_str!("sha256_pair_tail0.asm"),
            left_a = in(reg) left_a.as_ptr(),
            left_b = in(reg) left_b.as_ptr(),
            right_a = in(reg) right_a.as_ptr(),
            right_b = in(reg) right_b.as_ptr(),
            left_output = in(reg) left_digest.as_mut_ptr(),
            right_output = in(reg) right_digest.as_mut_ptr(),
            state = in(reg) IV.as_ptr(),
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            fixed_wk = in(reg) FINAL_64_WK.0.as_ptr(),
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack),
        );
    }
    (Digest(left_digest), Digest(right_digest))
}
