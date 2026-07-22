use super::{
    super::{DIGEST_LENGTH, Digest, IV},
    BMT_NODE_LEN, MMR_NODE_LEN, POSITION_LEN,
};

/// Wrapper that aligns constant tables for aligned vector loads.
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

/// Shuffle mask converting between byte and word endianness.
static BYTE_SWAP_MASK: Align16<[u8; 16]> =
    Align16([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]);

/// The `0x80` terminator following the 8-byte message tail in the MMR node's
/// padding block (message ends 8 bytes into the second block).
static FINAL_72_PAD: Align16<[u32; 4]> = Align16([0, 0, 0x80000000, 0]);

/// The message bit length in the final words of the MMR node's padding block.
static FINAL_72_LENGTH: Align16<[u32; 4]> = Align16([0, 0, 0, (MMR_NODE_LEN * 8) as u32]);

/// The `0x80` terminator opening the BMT node's padding block (the message
/// fills the first block exactly, leaving no tail).
static FINAL_64_PAD: Align16<[u32; 4]> = Align16([0x80000000, 0, 0, 0]);

/// The message bit length in the final words of the BMT node's padding block.
static FINAL_64_LENGTH: Align16<[u32; 4]> = Align16([0, 0, 0, (BMT_NODE_LEN * 8) as u32]);

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
pub unsafe fn hash_pair_64(
    left_a: &[u8; DIGEST_LENGTH],
    left_b: &[u8; DIGEST_LENGTH],
    right_a: &[u8; DIGEST_LENGTH],
    right_b: &[u8; DIGEST_LENGTH],
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
            include_str!("sha256_pair_block1_64.asm"),
            include_str!("sha256_pair_tail0.asm"),
            include_str!("sha256_pair_finish.asm"),
            left_a = in(reg) left_a.as_ptr(),
            left_b = in(reg) left_b.as_ptr(),
            right_a = in(reg) right_a.as_ptr(),
            right_b = in(reg) right_b.as_ptr(),
            left_output = in(reg) left_digest.as_mut_ptr(),
            right_output = in(reg) right_digest.as_mut_ptr(),
            state = in(reg) IV.as_ptr(),
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            pad = in(reg) FINAL_64_PAD.0.as_ptr(),
            len = in(reg) FINAL_64_LENGTH.0.as_ptr(),
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
        );
    }
    (Digest(left_digest), Digest(right_digest))
}
