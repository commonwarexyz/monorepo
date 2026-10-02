//! A lane sample that is not SHA-256 (fairness audit of 2026-10-02, J17):
//! arrays of independent ARX mixing rounds — the add / xor / rotate quarter
//! round of the ChaCha family, rotations 16, 12, 8 and 7 — which the lane
//! functor lifts to AVX-512 ×16, AVX2 ×8 and NEON ×4 kernels like the
//! SHA-256 sites of `tests/samples/lanes`. Its cones join the generated
//! lanewise-lemma libraries (`lemmas/lanes/<target>.core`, `tests/opt_lanes.rs`)
//! so those golden files do not cover only the benchmark's kernel.
#![forbid(unsafe_code)]

use sandblaster::prelude::*;

/// One ARX quarter round over four words.
pub fn quarter(s: [u32; 4]) -> [u32; 4] {
    let a1 = s[0].wrapping_add(s[1]);
    let d1 = (s[3] ^ a1).rotate_left(16);
    let c1 = s[2].wrapping_add(d1);
    let b1 = (s[1] ^ c1).rotate_left(12);
    let a2 = a1.wrapping_add(b1);
    let d2 = (d1 ^ a2).rotate_left(8);
    let c2 = c1.wrapping_add(d2);
    let b2 = (b1 ^ c2).rotate_left(7);
    [a2, b2, c2, d2]
}

/// Sixteen independent rounds (AVX-512 ×16).
pub fn quarter_x16(s: &[[u32; 4]; 16]) -> [[u32; 4]; 16] {
    [quarter(s[0]), quarter(s[1]), quarter(s[2]), quarter(s[3]), quarter(s[4]), quarter(s[5]), quarter(s[6]), quarter(s[7]), quarter(s[8]), quarter(s[9]), quarter(s[10]), quarter(s[11]), quarter(s[12]), quarter(s[13]), quarter(s[14]), quarter(s[15])]
}

/// Eight independent rounds (AVX2 ×8).
pub fn quarter_x8(s: &[[u32; 4]; 8]) -> [[u32; 4]; 8] {
    [quarter(s[0]), quarter(s[1]), quarter(s[2]), quarter(s[3]), quarter(s[4]), quarter(s[5]), quarter(s[6]), quarter(s[7])]
}

/// Four independent rounds (NEON ×4).
pub fn quarter_x4(s: &[[u32; 4]; 4]) -> [[u32; 4]; 4] {
    [quarter(s[0]), quarter(s[1]), quarter(s[2]), quarter(s[3])]
}
