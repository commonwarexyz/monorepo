use super::{
    super::{Digest, DIGEST_LENGTH, IV},
    NODE_LEN,
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

/// Hash two node-shaped messages with interleaved SHA2 instructions: one full
/// block plus a compile-time constant padding block each.
///
/// # Safety
///
/// The `sha2` target feature must be available.
#[allow(asm_sub_register)]
#[target_feature(enable = "sha2")]
pub unsafe fn hash_pair_72(left: &[u8; NODE_LEN], right: &[u8; NODE_LEN]) -> (Digest, Digest) {
    let mut left_digest = [0u8; DIGEST_LENGTH];
    let mut right_digest = [0u8; DIGEST_LENGTH];
    // SAFETY: The inputs and outputs are properly sized buffers, the caller
    // guarantees the SHA2 instructions are available, and all registers
    // written by the asm are listed as outputs.
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
            st1.16b {{v0, v1}}, [{left_output}]
            st1.16b {{v2, v3}}, [{right_output}]
            ",
            left = inout(reg) left.as_ptr() => _,
            right = inout(reg) right.as_ptr() => _,
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
