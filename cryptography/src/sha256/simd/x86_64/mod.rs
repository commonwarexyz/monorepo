use super::{digest, final_blocks, Align16, Digest, K, STATE, BLOCK_LENGTH};

static BYTE_SWAP_MASK: Align16<[u8; 16]> =
    Align16([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]);
static INITIAL_STATE: Align16<[u32; 8]> = Align16(STATE);
static FINAL_72_PAD: Align16<[u32; 4]> = Align16([0, 0, 0x80000000, 0]);
static FINAL_72_LENGTH: Align16<[u32; 4]> = Align16([0, 0, 0, 72 * 8]);

pub fn hash_pair(left: &[u8], right: &[u8]) -> (Digest, Digest) {
    debug_assert_eq!(left.len(), right.len());

    if left.len() == 72 {
        let mut output = core::mem::MaybeUninit::<[Digest; 2]>::uninit();
        // SAFETY: This backend is only dispatched after SHA-NI, AVX2, SSSE3, and SSE4.1 are
        // available. The branch checks that both slice pointers are valid for the 72 bytes read
        // by `hash_pair_72`, which writes exactly two initialized digests into `output`.
        unsafe {
            hash_pair_72(
                output.as_mut_ptr().cast::<u8>(),
                left.as_ptr(),
                right.as_ptr(),
            );
            let [left, right] = output.assume_init();
            return (left, right);
        }
    }

    let mut left_state = STATE;
    let mut right_state = STATE;
    let blocks = left.len() / BLOCK_LENGTH;
    // SAFETY: This backend is only dispatched after SHA-NI, AVX2, SSSE3, and SSE4.1 are
    // available. `blocks` is derived from the equal slice length, so both pointers are valid for
    // `blocks * BLOCK_LENGTH` bytes, and the state pointers come from exclusive local mutable
    // references.
    unsafe {
        compress_blocks_pair(
            left.as_ptr(),
            right.as_ptr(),
            blocks,
            &mut left_state,
            &mut right_state,
        );
    }

    let (left_final, final_block_count) = final_blocks(left);
    let (right_final, _) = final_blocks(right);
    // SAFETY: This backend is only dispatched after SHA-NI, AVX2, SSSE3, and SSE4.1 are
    // available. `final_blocks` returns stack buffers with enough initialized blocks for
    // `final_block_count`, and the state pointers come from exclusive local mutable references.
    unsafe {
        compress_blocks_pair(
            left_final.as_ptr().cast(),
            right_final.as_ptr().cast(),
            final_block_count,
            &mut left_state,
            &mut right_state,
        );
    }

    (digest(left_state), digest(right_state))
}

#[allow(asm_sub_register)]
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
unsafe fn hash_pair_72(output: *mut u8, left: *const u8, right: *const u8) {
    // SAFETY: Callers pass input pointers valid for 72 bytes and an output pointer valid for
    // 64 bytes. The target feature enables every instruction used here, and all registers
    // written by the asm are listed as outputs.
    unsafe {
        core::arch::asm!(
            concat!(
                include_str!("sha256_2x_macros.asm"),
                include_str!("sha256_72_2x.asm"),
            ),
            output = in(reg) output,
            left = in(reg) left,
            right = in(reg) right,
            state = in(reg) INITIAL_STATE.0.as_ptr(),
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
}

#[allow(asm_sub_register)]
#[target_feature(enable = "sha,avx2,ssse3,sse4.1")]
unsafe fn compress_blocks_pair(
    left: *const u8,
    right: *const u8,
    blocks: usize,
    left_state: &mut [u32; 8],
    right_state: &mut [u32; 8],
) {
    if blocks == 0 {
        return;
    }

    // SAFETY: Callers pass input pointers valid for `blocks * BLOCK_LENGTH` bytes and exclusive
    // state references. The target feature enables every instruction used here, and all
    // registers written by the asm are listed as outputs.
    unsafe {
        core::arch::asm!(
            concat!(
                include_str!("sha256_2x_macros.asm"),
                include_str!("sha256_rounds_2x.asm"),
            ),
            left = inout(reg) left => _,
            right = inout(reg) right => _,
            blocks = inout(reg) blocks => _,
            left_state = in(reg) left_state.as_mut_ptr(),
            right_state = in(reg) right_state.as_mut_ptr(),
            k = in(reg) K.0.as_ptr(),
            mask = in(reg) BYTE_SWAP_MASK.0.as_ptr(),
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _,
        );
    }
}
