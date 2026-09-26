use super::{
    super::{
        super::{BLOCK_LENGTH, DIGEST_LENGTH, Digest, IV},
        blocks::Blocks,
    },
    K,
};
use core::arch::aarch64::{uint32x4_t, vld1q_u32, vreinterpretq_u8_u32, vrev32q_u8, vst1q_u8};

/// The chaining states of both messages: left `abcd`, left `efgh`, right
/// `abcd`, right `efgh`.
type States = [uint32x4_t; 4];

/// Hash two messages of `len` bytes each, given as parts, with interleaved
/// SHA2 instructions.
///
/// # Safety
///
/// The `sha2` target feature must be available.
///
/// # Panics
///
/// Panics if either message is shorter than `len` bytes.
#[target_feature(enable = "sha2")]
pub unsafe fn hash_pair_equal(left: &[&[u8]], right: &[&[u8]], len: usize) -> (Digest, Digest) {
    let mut left_blocks = Blocks::new(left);
    let mut right_blocks = Blocks::new(right);
    // SAFETY: The caller guarantees the SHA2 instructions are available, and
    // both loads read within the 8-word initial hash value.
    unsafe {
        let abcd = vld1q_u32(IV.as_ptr());
        let efgh = vld1q_u32(IV.as_ptr().add(4));
        let mut states = [abcd, efgh, abcd, efgh];
        for _ in 0..len / BLOCK_LENGTH {
            compress(&mut states, left_blocks.next(), right_blocks.next());
        }
        let (left_padding, blocks) = left_blocks.finish(len);
        let (right_padding, _) = right_blocks.finish(len);
        let left_padding = left_padding.as_chunks::<BLOCK_LENGTH>().0;
        let right_padding = right_padding.as_chunks::<BLOCK_LENGTH>().0;
        compress(&mut states, &left_padding[0], &right_padding[0]);
        if blocks == 2 {
            compress(&mut states, &left_padding[1], &right_padding[1]);
        }
        (store(states[0], states[1]), store(states[2], states[3]))
    }
}

/// Compress one block into each message's state.
///
/// The rounds reuse the node kernels' assembly, which schedules them faster
/// than LLVM does for the equivalent intrinsics on Neoverse V2.
///
/// # Safety
///
/// The `sha2` target feature must be available.
#[inline(always)]
unsafe fn compress(states: &mut States, left: &[u8; BLOCK_LENGTH], right: &[u8; BLOCK_LENGTH]) {
    // SAFETY: The caller guarantees the SHA2 instructions are available. The
    // asm reads the two 64-byte blocks and the 64-word round-constant table,
    // writes no memory or stack, and every register it writes is declared.
    unsafe {
        core::arch::asm!(
            "ld1.16b {{v4, v5, v6, v7}}, [{left}]",
            "ld1.16b {{v8, v9, v10, v11}}, [{right}]",
            "rev32.16b v4, v4",
            "rev32.16b v5, v5",
            "rev32.16b v6, v6",
            "rev32.16b v7, v7",
            "rev32.16b v8, v8",
            "rev32.16b v9, v9",
            "rev32.16b v10, v10",
            "rev32.16b v11, v11",
            "mov.16b v20, v0",
            "mov.16b v21, v1",
            "mov.16b v22, v2",
            "mov.16b v23, v3",
            include_str!("sha256_rounds_2x.asm"),
            "add.4s v0, v0, v20",
            "add.4s v1, v1, v21",
            "add.4s v2, v2, v22",
            "add.4s v3, v3, v23",
            left = in(reg) left.as_ptr(),
            right = in(reg) right.as_ptr(),
            k = inout(reg) K.0.as_ptr() => _,
            inout("v0") states[0],
            inout("v1") states[1],
            inout("v2") states[2],
            inout("v3") states[3],
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v20") _, out("v21") _, out("v22") _,
            out("v23") _,
            options(nostack, readonly),
        );
    }
}

/// Serialize one state as its big-endian digest.
///
/// # Safety
///
/// NEON must be available.
#[inline(always)]
unsafe fn store(abcd: uint32x4_t, efgh: uint32x4_t) -> Digest {
    let mut digest = [0u8; DIGEST_LENGTH];
    // SAFETY: The caller guarantees NEON is available, and both stores write
    // within the 32-byte digest.
    unsafe {
        vst1q_u8(digest.as_mut_ptr(), vrev32q_u8(vreinterpretq_u8_u32(abcd)));
        vst1q_u8(
            digest.as_mut_ptr().add(16),
            vrev32q_u8(vreinterpretq_u8_u32(efgh)),
        );
    }
    Digest(digest)
}
