use super::{
    super::{BLOCK_LENGTH, DIGEST_LENGTH, Digest, IV, digest_from_state},
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

/// Hash two equal-length contiguous messages with interleaved SHA2 instructions.
///
/// # Safety
///
/// The `sha2` target feature must be available.
#[target_feature(enable = "sha2")]
pub unsafe fn hash_pair_bytes(left: &[u8], right: &[u8]) -> (Digest, Digest) {
    assert_eq!(left.len(), right.len());
    let mut left_state = IV;
    let mut right_state = IV;
    let (left_blocks, left_tail) = left.as_chunks::<BLOCK_LENGTH>();
    let (right_blocks, right_tail) = right.as_chunks::<BLOCK_LENGTH>();
    // SAFETY: The caller guarantees SHA2 support. Both inputs have equal length.
    unsafe {
        compress_pair(&mut left_state, &mut right_state, left_blocks, right_blocks);
    }

    let mut left_padding = [0u8; 2 * BLOCK_LENGTH];
    let mut right_padding = [0u8; 2 * BLOCK_LENGTH];
    left_padding[..left_tail.len()].copy_from_slice(left_tail);
    right_padding[..right_tail.len()].copy_from_slice(right_tail);
    left_padding[left_tail.len()] = 0x80;
    right_padding[right_tail.len()] = 0x80;
    let padding_len = if left_tail.len() < BLOCK_LENGTH - 8 {
        BLOCK_LENGTH
    } else {
        2 * BLOCK_LENGTH
    };
    let bit_len = (left.len() as u64).wrapping_mul(8).to_be_bytes();
    left_padding[padding_len - 8..padding_len].copy_from_slice(&bit_len);
    right_padding[padding_len - 8..padding_len].copy_from_slice(&bit_len);
    // SAFETY: The caller guarantees SHA2 support. Both padding buffers contain
    // the same number of complete blocks.
    unsafe {
        compress_pair(
            &mut left_state,
            &mut right_state,
            left_padding[..padding_len].as_chunks::<BLOCK_LENGTH>().0,
            right_padding[..padding_len].as_chunks::<BLOCK_LENGTH>().0,
        );
    }
    (
        Digest(digest_from_state(left_state)),
        Digest(digest_from_state(right_state)),
    )
}

/// Compress equal numbers of complete blocks into two independent states.
///
/// # Safety
///
/// The `sha2` target feature must be available.
#[target_feature(enable = "sha2")]
unsafe fn compress_pair(
    left_state: &mut [u32; 8],
    right_state: &mut [u32; 8],
    left: &[[u8; BLOCK_LENGTH]],
    right: &[[u8; BLOCK_LENGTH]],
) {
    assert_eq!(left.len(), right.len());
    if left.is_empty() {
        return;
    }
    // SAFETY: Each iteration reads exactly one complete block from each input.
    // The nonzero, equal block count bounds both advancing pointers. The state
    // buffers each hold eight words, SHA2 support is guaranteed by the caller,
    // and every register written by the assembly is declared as an output.
    unsafe {
        core::arch::asm!(
            "ld1.4s {{v0, v1}}, [{left_state}]",
            "ld1.4s {{v2, v3}}, [{right_state}]",
            "2:",
            "mov.16b v20, v0",
            "mov.16b v21, v1",
            "mov.16b v22, v2",
            "mov.16b v23, v3",
            "ld1.16b {{v4, v5, v6, v7}}, [{left}], #64",
            "ld1.16b {{v8, v9, v10, v11}}, [{right}], #64",
            "rev32.16b v4, v4",
            "rev32.16b v5, v5",
            "rev32.16b v6, v6",
            "rev32.16b v7, v7",
            "rev32.16b v8, v8",
            "rev32.16b v9, v9",
            "rev32.16b v10, v10",
            "rev32.16b v11, v11",
            "mov {k}, {k_start}",
            include_str!("sha256_rounds_2x.asm"),
            "add.4s v0, v0, v20",
            "add.4s v1, v1, v21",
            "add.4s v2, v2, v22",
            "add.4s v3, v3, v23",
            "subs {blocks}, {blocks}, #1",
            "b.ne 2b",
            "st1.4s {{v0, v1}}, [{left_state}]",
            "st1.4s {{v2, v3}}, [{right_state}]",
            left_state = in(reg) left_state.as_mut_ptr(),
            right_state = in(reg) right_state.as_mut_ptr(),
            left = inout(reg) left.as_ptr() => _,
            right = inout(reg) right.as_ptr() => _,
            blocks = inout(reg) left.len() => _,
            k = out(reg) _,
            k_start = in(reg) K.0.as_ptr(),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack)
        );
    }
}

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
