use super::{digest, digests, final_blocks, Digest, K, STATE, BLOCK_LENGTH, DIGEST_LENGTH};

pub fn hash_pair(left: &[u8], right: &[u8]) -> (Digest, Digest) {
    debug_assert_eq!(left.len(), right.len());

    if left.len() == 72 {
        // SAFETY: This backend is only dispatched after `sha2` is available. The branch
        // checks that both slice pointers are valid for the 72 bytes read by `hash_pair_72`.
        return unsafe { hash_pair_72(left.as_ptr(), right.as_ptr()) };
    }

    let mut left_state = STATE;
    let mut right_state = STATE;
    let blocks = left.len() / BLOCK_LENGTH;
    // SAFETY: This backend is only dispatched after `sha2` is available. `blocks` is derived
    // from the equal slice length, so both pointers are valid for `blocks * BLOCK_LENGTH` bytes,
    // and the state pointers come from exclusive local mutable references.
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
    // SAFETY: This backend is only dispatched after `sha2` is available. `final_blocks`
    // returns stack buffers with enough initialized blocks for `final_block_count`, and the
    // state pointers come from exclusive local mutable references.
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
#[target_feature(enable = "sha2")]
unsafe fn hash_pair_72(left: *const u8, right: *const u8) -> (Digest, Digest) {
    let mut output = [0u8; DIGEST_LENGTH * 2];
    // SAFETY: Callers pass input pointers valid for 72 bytes. `output` is a local 64-byte
    // buffer, the target feature enables the SHA2 instructions, and all registers written by
    // the asm are listed as outputs.
    unsafe {
        core::arch::asm!(
            "
            ld1.4s {{v0, v1}}, [{state}]
            mov.16b v2, v0
            mov.16b v3, v1
            mov.16b v20, v0
            mov.16b v21, v1
            mov.16b v22, v2
            mov.16b v23, v3

            ld1.16b {{v4, v5, v6, v7}}, [{left}], #64
            ld1.16b {{v8, v9, v10, v11}}, [{right}], #64
            rev32.16b v4, v4
            rev32.16b v5, v5
            rev32.16b v6, v6
            rev32.16b v7, v7
            rev32.16b v8, v8
            rev32.16b v9, v9
            rev32.16b v10, v10
            rev32.16b v11, v11
            mov {k}, {k_start}
            ",
            include_str!("sha256_rounds_2x.asm"),
            "
            add.4s v0, v0, v20
            add.4s v1, v1, v21
            add.4s v2, v2, v22
            add.4s v3, v3, v23

            mov.16b v20, v0
            mov.16b v21, v1
            mov.16b v22, v2
            mov.16b v23, v3

            movi.2d v4, #0
            movi.2d v5, #0
            movi.2d v6, #0
            movi.2d v7, #0
            movi.2d v8, #0
            movi.2d v9, #0
            movi.2d v10, #0
            movi.2d v11, #0
            ld1.8b {{v4}}, [{left}]
            ld1.8b {{v8}}, [{right}]
            mov {tmp:w}, #0x80
            ins v4.b[8], {tmp:w}
            ins v8.b[8], {tmp:w}
            rev32.16b v4, v4
            rev32.16b v8, v8
            mov {tmp:w}, #576
            ins v7.s[3], {tmp:w}
            ins v11.s[3], {tmp:w}
            mov {k}, {k_start}
            ",
            include_str!("sha256_rounds_2x.asm"),
            "
            add.4s v0, v0, v20
            add.4s v1, v1, v21
            add.4s v2, v2, v22
            add.4s v3, v3, v23
            rev32.16b v0, v0
            rev32.16b v1, v1
            rev32.16b v2, v2
            rev32.16b v3, v3
            st1.16b {{v0, v1, v2, v3}}, [{output}]
            ",
            left = inout(reg) left => _,
            right = inout(reg) right => _,
            output = inout(reg) output.as_mut_ptr() => _,
            tmp = out(reg) _,
            k = out(reg) _,
            k_start = in(reg) K.0.as_ptr(),
            state = in(reg) STATE.as_ptr(),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack)
        );
    }

    digests(output)
}

#[allow(asm_sub_register)]
#[target_feature(enable = "sha2")]
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

    // SAFETY: Callers pass input pointers valid for `blocks * BLOCK_LENGTH` bytes and
    // exclusive state references. The target feature enables the SHA2 instructions, and all
    // registers written by the asm are listed as outputs.
    unsafe {
        core::arch::asm!(
            "
            ld1.4s {{v0, v1}}, [{left_state}]
            ld1.4s {{v2, v3}}, [{right_state}]

        0:
            mov {k}, {k_start}
            mov.16b v20, v0
            mov.16b v21, v1
            mov.16b v22, v2
            mov.16b v23, v3

            ld1.16b {{v4, v5, v6, v7}}, [{left}], #64
            ld1.16b {{v8, v9, v10, v11}}, [{right}], #64
            rev32.16b v4, v4
            rev32.16b v5, v5
            rev32.16b v6, v6
            rev32.16b v7, v7
            rev32.16b v8, v8
            rev32.16b v9, v9
            rev32.16b v10, v10
            rev32.16b v11, v11
            ",
            include_str!("sha256_rounds_2x.asm"),
            "
            add.4s v0, v0, v20
            add.4s v1, v1, v21
            add.4s v2, v2, v22
            add.4s v3, v3, v23
            subs {blocks:x}, {blocks:x}, #1
            b.ne 0b

            st1.4s {{v0, v1}}, [{left_state}]
            st1.4s {{v2, v3}}, [{right_state}]
            ",
            left = inout(reg) left => _,
            right = inout(reg) right => _,
            blocks = inout(reg) blocks => _,
            k = out(reg) _,
            k_start = in(reg) K.0.as_ptr(),
            left_state = in(reg) left_state.as_mut_ptr(),
            right_state = in(reg) right_state.as_mut_ptr(),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            options(nostack)
        );
    }
}
