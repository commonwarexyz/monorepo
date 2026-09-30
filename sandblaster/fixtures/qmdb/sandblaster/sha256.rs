//! SHA-256 (FIPS 180-4) — the sandblaster port of `sha256.bend`.
//!
//! # Mapping from the Bend source
//!
//! | `sha256.bend` | here | note |
//! | --- | --- | --- |
//! | `Digest` (8 × `U32`) | [`Digest`] = `[u8; 32]` | §11.1: digests are bytes; `to_bytes` is applied once, at the end of every hash |
//! | `Words`, `Work` | `[u32; 64]` schedule, `[u32; 8]` working state | fixed-size arrays instead of 16/8-field records |
//! | `rotr(x, r, 32 - r)` | `x.rotate_right(r)` | whitelisted method (§3.4) |
//! | `small_sigma0/1`, `big_sigma0/1`, `choose`, `majority`, `add5` | same names | |
//! | `Work.round` | [`round`] | |
//! | `constants_first` ++ `constants_rest` | [`K`] (`K[0..16]` ++ `K[16..64]`) | one `const` table |
//! | `rounds_first`, `rounds_rest` | the three `for` loops of [`compress`] | 64-word schedule (FIPS 6.2.2) instead of a rolling 16-word window |
//! | `finish`, `compress` | [`finish`], [`compress`] | `compress` takes the fixed block `&[u8; 64]` (§9.7) |
//! | `be_word` | [`be_word`] (= `u32::from_be_bytes`) | |
//! | `blocks`, `initial`, `hash` | [`blocks`], [`INITIAL`], [`hash`] | `hash` pads with fixed arrays; bit length is the FIPS 64-bit length |
//! | `to_bytes`, `equal` | [`to_bytes`], [`equal`] | `equal` compares all 32 bytes |
//! | — | [`hash_1`] … [`hash_104`] | branch-free fixed-size hashes for the verifier's preimages (§9.7, §11.2) |
//! | — | [`compress_sha2`], [`compress_shani`] | hardware variants of `compress` (§9.3, §9.7) |
//!
//! Bend's `hash` is only specified for inputs of at most 65 536 bytes (its
//! bit length is a 32-bit product). [`hash`] here is total on every slice and
//! uses the FIPS 64-bit bit length (`len · 8 mod 2^64`); the two agree on
//! Bend's whole domain.
//!
//! # Obligations
//!
//! All arithmetic on words is explicitly wrapping (`wrapping_add`,
//! `rotate_right`, `>>` by a literal below 32), so the only obligations are
//! index/range bounds with literal or loop-bounded indices (`4 * t + 3 < 64`
//! for `t < 16`, `t - 16` for `16 ≤ t`, ...) and the padding offsets in
//! [`hash`] (`tail.len() < 64` from the `as_chunks` fact). All are linear;
//! see `qmdb/OBLIGATIONS.md`.
//!
//! # Hardware variants
//!
//! [`compress`] is the portable reference and the only compression function
//! the rest of the DSL calls. [`compress_sha2`] (aarch64 SHA2 instructions)
//! and [`compress_shani`] (x86_64 SHA-NI) carry `#[implements(compress)]`:
//! the checker proves each equal to [`compress`] (`VariantEquiv`, §9.3) and
//! the optimizer multiversions whole call trees onto them (§8.2). The DSL
//! never dispatches by hand. Both use memory only through the trusted
//! `sandblaster::arch` load/store helpers (§9.2) and contain no `unsafe`.

use sandblaster::prelude::*;

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vreinterpretq_u32_u8, vrev32q_u8, vsha256h2q_u32, vsha256hq_u32,
    vsha256su0q_u32, vsha256su1q_u32,
};
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use sandblaster::arch::aarch64::{load_u8x16, load_u32x4, store_u32x4};

#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_sha256msg1_epu32,
    _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8, _mm_shuffle_epi32,
};
#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
use sandblaster::arch::x86_64::{
    load_u8x16 as load_m128i_u8, load_u32x4 as load_m128i_u32, store_u32x4 as store_m128i_u32,
};

/// A SHA-256 digest: 32 bytes, big-endian words (DESIGN.md §11.1).
///
/// Bend's `Digest` holds the eight state words; the byte form is what every
/// hash preimage and the public API use, so the port converts once, at the
/// end of each hash ([`to_bytes`]).
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

/// [`K`] grouped by four (`K4[g][j] == K[4 * g + j]`): the constant operand
/// of each four-round group in the vector kernels.
pub const K4: [[u32; 4]; 16] = [
    [K[0], K[1], K[2], K[3]],
    [K[4], K[5], K[6], K[7]],
    [K[8], K[9], K[10], K[11]],
    [K[12], K[13], K[14], K[15]],
    [K[16], K[17], K[18], K[19]],
    [K[20], K[21], K[22], K[23]],
    [K[24], K[25], K[26], K[27]],
    [K[28], K[29], K[30], K[31]],
    [K[32], K[33], K[34], K[35]],
    [K[36], K[37], K[38], K[39]],
    [K[40], K[41], K[42], K[43]],
    [K[44], K[45], K[46], K[47]],
    [K[48], K[49], K[50], K[51]],
    [K[52], K[53], K[54], K[55]],
    [K[56], K[57], K[58], K[59]],
    [K[60], K[61], K[62], K[63]],
];

/// The initial hash value `H(0)` (FIPS 180-4 §5.3.3). Bend: `initial`.
pub const INITIAL: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
    0x5be0_cd19,
];

/// σ0 of the message schedule: `ROTR7 ⊕ ROTR18 ⊕ SHR3`.
#[inline]
pub(crate) fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3u32)
}

/// σ1 of the message schedule: `ROTR17 ⊕ ROTR19 ⊕ SHR10`.
#[inline]
pub(crate) fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10u32)
}

/// Σ0 of the compression rounds: `ROTR2 ⊕ ROTR13 ⊕ ROTR22`.
#[inline]
pub(crate) fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Σ1 of the compression rounds: `ROTR6 ⊕ ROTR11 ⊕ ROTR25`.
#[inline]
pub(crate) fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// `Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)`: each bit of `x` chooses `y` or `z`.
#[inline]
pub(crate) fn choose(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// `Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)`: bitwise majority.
#[inline]
pub(crate) fn majority(x: u32, y: u32, z: u32) -> u32 {
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
#[refines(crate::spec::sha256::compress)]
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

/// Whether two digests are equal, comparing all 32 bytes. Bend: `equal`
/// (which compares the eight words). Law: `digest_equal_sound`.
pub fn equal(left: &Digest, right: &Digest) -> bool {
    *left == *right
}

// ---------------------------------------------------------------------------
// Fixed-size hashes (DESIGN.md §9.5, §9.7, §11.2).
//
// Every hash preimage in the verifier has a fixed length (per instance: the
// chunk digest is `hash_N` and the graft `hash_{N+32}`, chosen by `config`),
// so each gets a branch-free function whose padding block is built from literals at literal
// indices. The optimizer can then specialize them per hardware variant:
// with a symbolic message, the padding words (and, for 64 bytes, the whole
// second block's schedule) fold to constants. Each is equal to `hash(msg)`.
// Lengths up to 55 bytes take one block, 56..=119 bytes take two. Each is
// `#[specialize]`: should the optimizer fail to specialize one (for either
// instance, portable or per hardware variant), the build fails instead of
// silently shipping the generic code (§8.2).
// ---------------------------------------------------------------------------

/// SHA-256 of 1 byte (the N = 1 partial-chunk digest `H(chunk)`).
#[specialize]
#[refines(crate::spec::sha256::sha256)]
pub fn hash_1(msg: &[u8; 1]) -> Digest {
    let mut block = [0u8; 64];
    block[0..1].copy_from_slice(msg);
    block[1] = 0x80;
    block[56..64].copy_from_slice(&8u64.to_be_bytes());
    to_bytes(compress(INITIAL, &block))
}

/// SHA-256 of 32 bytes (the N = 32 partial-chunk digest `H(chunk)`).
#[specialize]
#[refines(crate::spec::sha256::sha256)]
pub fn hash_32(msg: &[u8; 32]) -> Digest {
    let mut block = [0u8; 64];
    block[0..32].copy_from_slice(msg);
    block[32] = 0x80;
    block[56..64].copy_from_slice(&(32u64 * 8).to_be_bytes());
    to_bytes(compress(INITIAL, &block))
}

/// SHA-256 of 33 bytes (the N = 1 graft `H(chunk ‖ subtree)`, height 3).
#[specialize]
#[refines(crate::spec::sha256::sha256)]
pub fn hash_33(msg: &[u8; 33]) -> Digest {
    let mut block = [0u8; 64];
    block[0..33].copy_from_slice(msg);
    block[33] = 0x80;
    block[56..64].copy_from_slice(&(33u64 * 8).to_be_bytes());
    to_bytes(compress(INITIAL, &block))
}

/// SHA-256 of 40 bytes (the tree root seal `H(u64be(leaves) ‖ peaks)`).
#[specialize]
#[refines(crate::spec::sha256::sha256)]
pub fn hash_40(msg: &[u8; 40]) -> Digest {
    let mut block = [0u8; 64];
    block[0..40].copy_from_slice(msg);
    block[40] = 0x80;
    block[56..64].copy_from_slice(&(40u64 * 8).to_be_bytes());
    to_bytes(compress(INITIAL, &block))
}

/// SHA-256 of 48 bytes (the tree root seal with an inactive-peak count,
/// `H(u64be(leaves) ‖ u64be(inactive) ‖ peaks)`).
#[specialize]
#[refines(crate::spec::sha256::sha256)]
pub fn hash_48(msg: &[u8; 48]) -> Digest {
    let mut block = [0u8; 64];
    block[0..48].copy_from_slice(msg);
    block[48] = 0x80;
    block[56..64].copy_from_slice(&(48u64 * 8).to_be_bytes());
    to_bytes(compress(INITIAL, &block))
}

/// SHA-256 of 64 bytes (the peak fold `H(a ‖ b)`, the canonical root
/// `H(ops_root ‖ grafted_root)` and the N = 32 graft `H(chunk ‖ subtree)`,
/// height 8). The second block is pure padding.
#[specialize]
#[refines(crate::spec::sha256::sha256)]
pub fn hash_64(msg: &[u8; 64]) -> Digest {
    let mut second = [0u8; 64];
    second[0] = 0x80;
    second[56..64].copy_from_slice(&(64u64 * 8).to_be_bytes());
    to_bytes(compress(compress(INITIAL, msg), &second))
}

/// SHA-256 of 72 bytes (the MMR node `H(u64be(position) ‖ left ‖ right)`).
#[specialize]
#[refines(crate::spec::sha256::sha256)]
pub fn hash_72(msg: &[u8; 72]) -> Digest {
    let mut first = [0u8; 64];
    first.copy_from_slice(&msg[0..64]);
    let mut second = [0u8; 64];
    second[0..8].copy_from_slice(&msg[64..72]);
    second[8] = 0x80;
    second[56..64].copy_from_slice(&(72u64 * 8).to_be_bytes());
    let mid = compress(INITIAL, &first);
    let state = compress(mid, &second);
    // these two compressions are SHA-256 of the 72 bytes (PROOF.rs: `sha256_72`)
    proof! { crate::proof::sha256_72(msg, mid, state); }
    to_bytes(state)
}

/// SHA-256 of 73 bytes (the MMR leaf `H(u64be(position) ‖ 0xD2 ‖ key ‖
/// value)`).
#[specialize]
#[refines(crate::spec::sha256::sha256)]
pub fn hash_73(msg: &[u8; 73]) -> Digest {
    let mut first = [0u8; 64];
    first.copy_from_slice(&msg[0..64]);
    let mut second = [0u8; 64];
    second[0..9].copy_from_slice(&msg[64..73]);
    second[9] = 0x80;
    second[56..64].copy_from_slice(&(73u64 * 8).to_be_bytes());
    let mid = compress(INITIAL, &first);
    let state = compress(mid, &second);
    // these two compressions are SHA-256 of the 73 bytes (PROOF.rs: `sha256_73`)
    proof! { crate::proof::sha256_73(msg, mid, state); }
    to_bytes(state)
}

/// SHA-256 of 104 bytes (the canonical root with a partial chunk,
/// `H(ops_root ‖ grafted_root ‖ u64be(next_bit) ‖ partial_digest)`).
#[specialize]
#[refines(crate::spec::sha256::sha256)]
pub fn hash_104(msg: &[u8; 104]) -> Digest {
    let mut first = [0u8; 64];
    first.copy_from_slice(&msg[0..64]);
    let mut second = [0u8; 64];
    second[0..40].copy_from_slice(&msg[64..104]);
    second[40] = 0x80;
    second[56..64].copy_from_slice(&(104u64 * 8).to_be_bytes());
    let mid = compress(INITIAL, &first);
    let state = compress(mid, &second);
    // these two compressions are SHA-256 of the 104 bytes (PROOF.rs: `sha256_104`)
    proof! { crate::proof::sha256_104(msg, mid, state); }
    to_bytes(state)
}

// ---------------------------------------------------------------------------
// aarch64: ARMv8 SHA2 instructions (DESIGN.md §9.2, §9.7).
//
// NEON vectors hold four state or schedule words, lane 0 first. The state is
// kept as `abcd` and `efgh`; each four-round group runs `SHA256H` (new abcd)
// and `SHA256H2` (new efgh, from the *pre-update* abcd) on `W + K`, and the
// schedule advances four words at a time with `SHA256SU0`/`SHA256SU1`.
// ---------------------------------------------------------------------------

/// Four message words of a 16-byte chunk: load, then byte-reverse each 32-bit
/// lane (`from_be_bytes` per lane, §9.2: `vrev32q_u8` + reinterpret is
/// `from_be_bytes` by definition).
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "sha2")]
#[inline]
fn be_words_sha2(chunk: &[u8; 16]) -> uint32x4_t {
    vreinterpretq_u32_u8(vrev32q_u8(load_u8x16(chunk)))
}

/// Four rounds with pre-added `wk = W[4g..4g+4] + K[4g..4g+4]`: returns the
/// new `(abcd, efgh)`. `vsha256h2q_u32` takes the pre-update `abcd`.
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "sha2")]
#[inline]
fn rounds4_sha2(abcd: uint32x4_t, efgh: uint32x4_t, wk: uint32x4_t) -> (uint32x4_t, uint32x4_t) {
    (vsha256hq_u32(abcd, efgh, wk), vsha256h2q_u32(efgh, abcd, wk))
}

/// The next four schedule words from the previous sixteen (`w0` oldest).
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "sha2")]
#[inline]
fn schedule_sha2(w0: uint32x4_t, w1: uint32x4_t, w2: uint32x4_t, w3: uint32x4_t) -> uint32x4_t {
    vsha256su1q_u32(vsha256su0q_u32(w0, w1), w2, w3)
}

/// `W + K` for one four-round group.
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "sha2")]
#[inline]
fn wk_sha2(w: uint32x4_t, k: &[u32; 4]) -> uint32x4_t {
    vaddq_u32(w, load_u32x4(k))
}

/// [`compress`] with the ARMv8 SHA2 instructions (DESIGN.md §9.7).
///
/// Proven equal to [`compress`] on every input (`VariantEquiv`, §9.3), group
/// by group: each `rounds4_sha2` call is four FIPS rounds and each
/// `schedule_sha2` call is four schedule steps.
///
/// # Safety
///
/// Safe to call from code whose feature set includes `sha2`. Elsewhere
/// `rustc` requires `unsafe`, and the caller must guarantee that the CPU
/// implements the ARMv8 SHA2 extension (the generated dispatcher does, §9.3).
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "sha2")]
#[implements(crate::sha256::compress)]
pub fn compress_sha2(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let (chunks, _) = block.as_chunks::<16>();
    let abcd_in = load_u32x4(&[state[0], state[1], state[2], state[3]]);
    let efgh_in = load_u32x4(&[state[4], state[5], state[6], state[7]]);

    let w0 = be_words_sha2(&chunks[0]);
    let w1 = be_words_sha2(&chunks[1]);
    let w2 = be_words_sha2(&chunks[2]);
    let w3 = be_words_sha2(&chunks[3]);
    let (abcd, efgh) = rounds4_sha2(abcd_in, efgh_in, wk_sha2(w0, &K4[0]));
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w1, &K4[1]));
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w2, &K4[2]));
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w3, &K4[3]));
    let w4 = schedule_sha2(w0, w1, w2, w3);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w4, &K4[4]));
    let w5 = schedule_sha2(w1, w2, w3, w4);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w5, &K4[5]));
    let w6 = schedule_sha2(w2, w3, w4, w5);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w6, &K4[6]));
    let w7 = schedule_sha2(w3, w4, w5, w6);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w7, &K4[7]));
    let w8 = schedule_sha2(w4, w5, w6, w7);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w8, &K4[8]));
    let w9 = schedule_sha2(w5, w6, w7, w8);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w9, &K4[9]));
    let w10 = schedule_sha2(w6, w7, w8, w9);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w10, &K4[10]));
    let w11 = schedule_sha2(w7, w8, w9, w10);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w11, &K4[11]));
    let w12 = schedule_sha2(w8, w9, w10, w11);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w12, &K4[12]));
    let w13 = schedule_sha2(w9, w10, w11, w12);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w13, &K4[13]));
    let w14 = schedule_sha2(w10, w11, w12, w13);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w14, &K4[14]));
    let w15 = schedule_sha2(w11, w12, w13, w14);
    let (abcd, efgh) = rounds4_sha2(abcd, efgh, wk_sha2(w15, &K4[15]));

    let abcd_out = store_u32x4(vaddq_u32(abcd, abcd_in));
    let efgh_out = store_u32x4(vaddq_u32(efgh, efgh_in));
    [
        abcd_out[0],
        abcd_out[1],
        abcd_out[2],
        abcd_out[3],
        efgh_out[0],
        efgh_out[1],
        efgh_out[2],
        efgh_out[3],
    ]
}

// ---------------------------------------------------------------------------
// x86_64: SHA-NI (DESIGN.md §9.2, §9.7). Compiled for x86_64 targets; not
// dispatched until its models have x86 hardware evidence (this machine's
// Rosetta has no SHA-NI).
//
// `__m128i` lanes are written high-to-low in Intel's names: the state is kept
// as `abef = [F, E, B, A]` and `cdgh = [H, G, D, C]` (32-bit lanes 0..3).
// Each `SHA256RNDS2` runs two rounds using the low two words of its `wk`
// operand; after the first call of a group, the old `abef` register already
// has the layout of the new `cdgh`, so the second call swaps roles.
// ---------------------------------------------------------------------------

/// `pshufb` mask reversing the bytes of every 32-bit lane.
#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
const BSWAP32_MASK: [u8; 16] = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12];

/// Four big-endian message words of a 16-byte chunk.
#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[inline]
fn be_words_shani(chunk: &[u8; 16]) -> __m128i {
    _mm_shuffle_epi8(load_m128i_u8(chunk), load_m128i_u8(&BSWAP32_MASK))
}

/// Four rounds with pre-added `wk`: returns the new `(abef, cdgh)`.
#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[inline]
fn rounds4_shani(abef: __m128i, cdgh: __m128i, wk: __m128i) -> (__m128i, __m128i) {
    let cdgh_next = _mm_sha256rnds2_epu32(cdgh, abef, wk);
    let abef_next = _mm_sha256rnds2_epu32(abef, cdgh_next, _mm_shuffle_epi32::<0x0E>(wk));
    (abef_next, cdgh_next)
}

/// The next four schedule words from the previous sixteen (`w0` oldest).
#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[inline]
fn schedule_shani(w0: __m128i, w1: __m128i, w2: __m128i, w3: __m128i) -> __m128i {
    let t = _mm_add_epi32(_mm_sha256msg1_epu32(w0, w1), _mm_alignr_epi8::<4>(w3, w2));
    _mm_sha256msg2_epu32(t, w3)
}

/// `W + K` for one four-round group.
#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[inline]
fn wk_shani(w: __m128i, k: &[u32; 4]) -> __m128i {
    _mm_add_epi32(w, load_m128i_u32(k))
}

/// [`compress`] with the x86 SHA extensions (DESIGN.md §9.7).
///
/// Proven equal to [`compress`] (`VariantEquiv`, §9.3). The instruction
/// sequence is the one of the `sha2` crate's x86 backend.
///
/// # Safety
///
/// Safe to call from code whose feature set includes
/// `sha,sse2,ssse3,sse4.1`. Elsewhere `rustc` requires `unsafe`, and the
/// caller must guarantee that the CPU implements them.
#[cfg(all(target_arch = "x86_64", target_endian = "little"))]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
#[implements(crate::sha256::compress)]
pub fn compress_shani(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let (chunks, _) = block.as_chunks::<16>();
    let dcba = load_m128i_u32(&[state[0], state[1], state[2], state[3]]);
    let hgfe = load_m128i_u32(&[state[4], state[5], state[6], state[7]]);
    let cdab = _mm_shuffle_epi32::<0xB1>(dcba);
    let efgh = _mm_shuffle_epi32::<0x1B>(hgfe);
    let abef_in = _mm_alignr_epi8::<8>(cdab, efgh);
    let cdgh_in = _mm_blend_epi16::<0xF0>(efgh, cdab);

    let w0 = be_words_shani(&chunks[0]);
    let w1 = be_words_shani(&chunks[1]);
    let w2 = be_words_shani(&chunks[2]);
    let w3 = be_words_shani(&chunks[3]);
    let (abef, cdgh) = rounds4_shani(abef_in, cdgh_in, wk_shani(w0, &K4[0]));
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w1, &K4[1]));
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w2, &K4[2]));
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w3, &K4[3]));
    let w4 = schedule_shani(w0, w1, w2, w3);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w4, &K4[4]));
    let w5 = schedule_shani(w1, w2, w3, w4);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w5, &K4[5]));
    let w6 = schedule_shani(w2, w3, w4, w5);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w6, &K4[6]));
    let w7 = schedule_shani(w3, w4, w5, w6);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w7, &K4[7]));
    let w8 = schedule_shani(w4, w5, w6, w7);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w8, &K4[8]));
    let w9 = schedule_shani(w5, w6, w7, w8);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w9, &K4[9]));
    let w10 = schedule_shani(w6, w7, w8, w9);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w10, &K4[10]));
    let w11 = schedule_shani(w7, w8, w9, w10);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w11, &K4[11]));
    let w12 = schedule_shani(w8, w9, w10, w11);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w12, &K4[12]));
    let w13 = schedule_shani(w9, w10, w11, w12);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w13, &K4[13]));
    let w14 = schedule_shani(w10, w11, w12, w13);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w14, &K4[14]));
    let w15 = schedule_shani(w11, w12, w13, w14);
    let (abef, cdgh) = rounds4_shani(abef, cdgh, wk_shani(w15, &K4[15]));

    let abef = _mm_add_epi32(abef, abef_in);
    let cdgh = _mm_add_epi32(cdgh, cdgh_in);
    let feba = _mm_shuffle_epi32::<0x1B>(abef);
    let dchg = _mm_shuffle_epi32::<0xB1>(cdgh);
    let dcba = _mm_blend_epi16::<0xF0>(feba, dchg);
    let hgef = _mm_alignr_epi8::<8>(dchg, feba);
    let low = store_m128i_u32(dcba);
    let high = store_m128i_u32(hgef);
    [low[0], low[1], low[2], low[3], high[0], high[1], high[2], high[3]]
}
