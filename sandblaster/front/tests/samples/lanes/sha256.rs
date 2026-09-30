//! SHA-256 (FIPS 180-4), the portable code of `sandblaster/fixtures/qmdb/sandblaster/sha256.rs`
//! without its hardware variants: the callee of the lane sites of
//! `sites.rs` (plan O10, gate G7: the lane kernels compile for x86_64).

use sandblaster::prelude::*;

/// A SHA-256 digest: 32 bytes, big-endian words.
pub type Digest = [u8; 32];

/// The round constants `K` (FIPS 180-4 §4.2.2).
///
/// Bend splits them into `constants_first` (`K[0..16]`, used with the 16
/// message words) and `constants_rest` (`K[16..64]`, used with scheduled
/// words).
pub const K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
    0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
    0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
    0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
    0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
    0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
    0xc671_78f2,
];

/// The initial hash value `H(0)` (FIPS 180-4 §5.3.3). Bend: `initial`.
pub const INITIAL: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
    0x5be0_cd19,
];

/// σ0 of the message schedule: `ROTR7 ⊕ ROTR18 ⊕ SHR3`.
#[inline]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3u32)
}

/// σ1 of the message schedule: `ROTR17 ⊕ ROTR19 ⊕ SHR10`.
#[inline]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10u32)
}

/// Σ0 of the compression rounds: `ROTR2 ⊕ ROTR13 ⊕ ROTR22`.
#[inline]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Σ1 of the compression rounds: `ROTR6 ⊕ ROTR11 ⊕ ROTR25`.
#[inline]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// `Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)`: each bit of `x` chooses `y` or `z`.
#[inline]
fn choose(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// `Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)`: bitwise majority.
#[inline]
fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Wrapping sum of five words, left to right (`T1` of a round).
#[inline]
fn add5(a: u32, b: u32, c: u32, d: u32, e: u32) -> u32 {
    a.wrapping_add(b).wrapping_add(c).wrapping_add(d).wrapping_add(e)
}

/// One compression round on the working state `[a, b, c, d, e, f, g, h]`
/// with round constant `k` and schedule word `w` (FIPS 180-4 §6.2.2 step 3).
/// Bend: `Work.round`.
#[inline]
fn round(work: [u32; 8], k: u32, w: u32) -> [u32; 8] {
    let a = work[0];
    let b = work[1];
    let c = work[2];
    let d = work[3];
    let e = work[4];
    let f = work[5];
    let g = work[6];
    let h = work[7];
    let t1 = add5(h, big_sigma1(e), choose(e, f, g), k, w);
    let t2 = big_sigma0(a).wrapping_add(majority(a, b, c));
    [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g]
}

/// Add the compressed working state back into the chaining state
/// (FIPS 180-4 §6.2.2 step 4). Bend: `finish`.
#[inline]
fn finish(state: [u32; 8], work: [u32; 8]) -> [u32; 8] {
    [
        state[0].wrapping_add(work[0]),
        state[1].wrapping_add(work[1]),
        state[2].wrapping_add(work[2]),
        state[3].wrapping_add(work[3]),
        state[4].wrapping_add(work[4]),
        state[5].wrapping_add(work[5]),
        state[6].wrapping_add(work[6]),
        state[7].wrapping_add(work[7]),
    ]
}

/// The big-endian word `a ‖ b ‖ c ‖ d`. Bend: `be_word`.
#[inline]
fn be_word(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

/// The SHA-256 compression function on one 64-byte block (FIPS 180-4
/// §6.2.2): the portable reference of every hardware variant.
///
/// Bend: `compress` with `rounds_first` (the 16 message words with
/// `constants_first`) and `rounds_rest` (48 scheduled words with
/// `constants_rest`). The Bend version slides a 16-word window; this one
/// materializes the 64-word schedule first, which computes the same words:
/// `next = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]`, summed in Bend's
/// order.
pub fn compress(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let mut w = [0u32; 64];
    for t in 0usize..16 {
        w[t] = be_word(block[4 * t], block[4 * t + 1], block[4 * t + 2], block[4 * t + 3]);
    }
    for t in 16usize..64 {
        w[t] = small_sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }
    let mut work = state;
    for t in 0usize..64 {
        work = round(work, K[t], w[t]);
    }
    finish(state, work)
}

/// Serialize the chaining state as a big-endian digest. Bend: `to_bytes`.
pub fn to_bytes(state: [u32; 8]) -> Digest {
    let mut out = [0u8; 32];
    for i in 0usize..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

/// SHA-256 of 64 bytes (the peak fold `H(a ‖ b)`, the canonical root
/// `H(ops_root ‖ grafted_root)` and the N = 32 graft `H(chunk ‖ subtree)`,
/// height 8). The second block is pure padding.
pub fn hash_64(msg: &[u8; 64]) -> Digest {
    let mut second = [0u8; 64];
    second[0] = 0x80;
    second[56..64].copy_from_slice(&(64u64 * 8).to_be_bytes());
    to_bytes(compress(compress(INITIAL, msg), &second))
}

