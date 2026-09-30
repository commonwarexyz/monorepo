//! Full SHA-256 compressions assembled from the intrinsic models.
//!
//! These are the hardware kernels of DESIGN.md §9.7 (`compress_sha2`,
//! `compress_shani`) written against the *models* instead of `core::arch`:
//! statement for statement the sequences of the `sha2` crate's backends
//! (`sha2-0.11.0/src/sha256/aarch64_sha2.rs` and `x86_sha.rs`), specialized to
//! one block. [`crate::consistency`] checks that each equals the plain FIPS
//! 180-4 [`crate::fips::compress`]. That is the executable form of the
//! `VariantEquiv` obligation phase 3 proves in the kernel (§9.3), and it
//! exercises every packing convention at once: the vrev32 / pshufb big-endian
//! loads, H2's reversed argument order and pre-update `abcd`, the ABEF/CDGH
//! state layout, the `W + K` split of SHA256RNDS2 and the schedule
//! instructions.
#![forbid(unsafe_code)]

use crate::aarch64 as a64;
use crate::fips::K;
use crate::x86_64 as x86;

/// `K_t .. K_{t+3}` as a four-word array (what `vld1q_u32(&K32[t])` reads).
fn k4(t: usize) -> [u32; 4] {
    [K[t], K[t + 1], K[t + 2], K[t + 3]]
}

/// 16 bytes of the block starting at `16 * i`.
fn block16(block: &[u8; 64], i: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    b.copy_from_slice(&block[16 * i..16 * i + 16]);
    b
}

/// SHA-256 compression of one block from the aarch64 NEON/SHA2 models, in the
/// `sha2` crate's `aarch64_sha2::compress` sequence.
pub fn compress_aarch64_models(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    // Load state into vectors.
    let mut abcd = a64::vld1q_u32(&[state[0], state[1], state[2], state[3]]);
    let mut efgh = a64::vld1q_u32(&[state[4], state[5], state[6], state[7]]);

    // Keep original state values.
    let abcd_orig = abcd;
    let efgh_orig = efgh;

    // Load the message block into vectors (big-endian words via REV32).
    let load =
        |i: usize| a64::vreinterpretq_u32_u8(a64::vrev32q_u8(a64::vld1q_u8(&block16(block, i))));
    let mut s0 = load(0);
    let mut s1 = load(1);
    let mut s2 = load(2);
    let mut s3 = load(3);

    // Four rounds: W + K, then SHA256H on the pre-update abcd and SHA256H2
    // with efgh first and the *pre-update* abcd second.
    macro_rules! rounds4 {
        ($s:expr, $t:expr) => {{
            let tmp = a64::vaddq_u32($s, a64::vld1q_u32(&k4($t)));
            let abcd_prev = abcd;
            abcd = a64::vsha256hq_u32(abcd_prev, efgh, tmp);
            efgh = a64::vsha256h2q_u32(efgh, abcd_prev, tmp);
        }};
    }

    rounds4!(s0, 0);
    rounds4!(s1, 4);
    rounds4!(s2, 8);
    rounds4!(s3, 12);

    for t in (16..64).step_by(16) {
        s0 = a64::vsha256su1q_u32(a64::vsha256su0q_u32(s0, s1), s2, s3);
        rounds4!(s0, t);
        s1 = a64::vsha256su1q_u32(a64::vsha256su0q_u32(s1, s2), s3, s0);
        rounds4!(s1, t + 4);
        s2 = a64::vsha256su1q_u32(a64::vsha256su0q_u32(s2, s3), s0, s1);
        rounds4!(s2, t + 8);
        s3 = a64::vsha256su1q_u32(a64::vsha256su0q_u32(s3, s0), s1, s2);
        rounds4!(s3, t + 12);
    }

    // Add the block-specific state to the original state.
    abcd = a64::vaddq_u32(abcd, abcd_orig);
    efgh = a64::vaddq_u32(efgh, efgh_orig);

    // Store vectors into state.
    let lo = a64::vst1q_u32(abcd);
    let hi = a64::vst1q_u32(efgh);
    [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]
}

/// The `sha2` crate's `K32X4`: round constants in groups of four, reversed so
/// that `_mm_set_epi32(k[0], k[1], k[2], k[3])` puts `K_{4i}` in lane 0.
pub const K32X4: [[u32; 4]; 16] = {
    let mut res = [[0u32; 4]; 16];
    let mut i = 0;
    while i < 16 {
        res[i] = [K[4 * i + 3], K[4 * i + 2], K[4 * i + 1], K[4 * i]];
        i += 1;
    }
    res
};

/// Little-endian bytes of four words (the memory image of a `[u32; 4]` that
/// `_mm_loadu_si128(state.as_ptr().cast())` reads).
fn le_bytes4(w: [u32; 4]) -> [u8; 16] {
    x86::from_u32x4(w)
}

/// The byte-swap mask of `x86_sha.rs` (`MASK`): reverses the bytes of each
/// 32-bit lane under PSHUFB.
pub fn shani_bswap_mask() -> x86::M128i {
    x86::_mm_set_epi64x(
        0x0C0D_0E0F_0809_0A0Bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    )
}

/// `schedule(v0, v1, v2, v3)` of `x86_sha.rs`: the next four schedule words.
pub fn shani_schedule(
    v0: x86::M128i,
    v1: x86::M128i,
    v2: x86::M128i,
    v3: x86::M128i,
) -> x86::M128i {
    let t1 = x86::_mm_sha256msg1_epu32(v0, v1);
    let t2 = x86::_mm_alignr_epi8(v3, v2, 4);
    let t3 = x86::_mm_add_epi32(t1, t2);
    x86::_mm_sha256msg2_epu32(t3, v3)
}

/// `rounds4!(abef, cdgh, rest, i)` of `x86_sha.rs`: four rounds as two
/// SHA256RNDS2, the second on the upper `W + K` pair (shuffle `0x0E`) with the
/// state registers swapped. Returns the new `(abef, cdgh)`.
pub fn shani_rounds4(
    abef: x86::M128i,
    cdgh: x86::M128i,
    rest: x86::M128i,
    i: usize,
) -> (x86::M128i, x86::M128i) {
    let k = K32X4[i];
    let kv = x86::_mm_set_epi32(k[0] as i32, k[1] as i32, k[2] as i32, k[3] as i32);
    let t1 = x86::_mm_add_epi32(rest, kv);
    let cdgh = x86::_mm_sha256rnds2_epu32(cdgh, abef, t1);
    let t2 = x86::_mm_shuffle_epi32(t1, 0x0E);
    let abef = x86::_mm_sha256rnds2_epu32(abef, cdgh, t2);
    (abef, cdgh)
}

/// The state prologue of `x86_sha.rs`: `[a..h]` → `(abef, cdgh)` with lanes
/// `abef = [f, e, b, a]`, `cdgh = [h, g, d, c]`.
pub fn shani_pack_state(state: [u32; 8]) -> (x86::M128i, x86::M128i) {
    let dcba = x86::_mm_loadu_si128(&le_bytes4([state[0], state[1], state[2], state[3]]));
    let hgfe = x86::_mm_loadu_si128(&le_bytes4([state[4], state[5], state[6], state[7]]));
    let cdab = x86::_mm_shuffle_epi32(dcba, 0xB1);
    let efgh = x86::_mm_shuffle_epi32(hgfe, 0x1B);
    let abef = x86::_mm_alignr_epi8(cdab, efgh, 8);
    let cdgh = x86::_mm_blend_epi16(efgh, cdab, 0xF0);
    (abef, cdgh)
}

/// The state epilogue of `x86_sha.rs`, inverse of [`shani_pack_state`].
pub fn shani_unpack_state(abef: x86::M128i, cdgh: x86::M128i) -> [u32; 8] {
    let feba = x86::_mm_shuffle_epi32(abef, 0x1B);
    let dchg = x86::_mm_shuffle_epi32(cdgh, 0xB1);
    let dcba = x86::_mm_blend_epi16(feba, dchg, 0xF0);
    let hgef = x86::_mm_alignr_epi8(dchg, feba, 8);
    let lo = x86::view_u32(x86::_mm_storeu_si128(dcba));
    let hi = x86::view_u32(x86::_mm_storeu_si128(hgef));
    [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3]]
}

/// SHA-256 compression of one block from the x86 SSE/SHA-NI models, in the
/// `sha2` crate's `x86_sha::compress` sequence.
pub fn compress_x86_models(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let mask = shani_bswap_mask();
    let (mut abef, mut cdgh) = shani_pack_state(state);
    let abef_save = abef;
    let cdgh_save = cdgh;

    let load = |i: usize| x86::_mm_shuffle_epi8(x86::_mm_loadu_si128(&block16(block, i)), mask);
    let mut w0 = load(0);
    let mut w1 = load(1);
    let mut w2 = load(2);
    let mut w3 = load(3);
    let mut w4;

    macro_rules! rounds4 {
        ($rest:expr, $i:expr) => {{
            (abef, cdgh) = shani_rounds4(abef, cdgh, $rest, $i);
        }};
    }
    macro_rules! schedule_rounds4 {
        ($w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr, $i:expr) => {{
            $w4 = shani_schedule($w0, $w1, $w2, $w3);
            rounds4!($w4, $i);
        }};
    }

    rounds4!(w0, 0);
    rounds4!(w1, 1);
    rounds4!(w2, 2);
    rounds4!(w3, 3);
    schedule_rounds4!(w0, w1, w2, w3, w4, 4);
    schedule_rounds4!(w1, w2, w3, w4, w0, 5);
    schedule_rounds4!(w2, w3, w4, w0, w1, 6);
    schedule_rounds4!(w3, w4, w0, w1, w2, 7);
    schedule_rounds4!(w4, w0, w1, w2, w3, 8);
    schedule_rounds4!(w0, w1, w2, w3, w4, 9);
    schedule_rounds4!(w1, w2, w3, w4, w0, 10);
    schedule_rounds4!(w2, w3, w4, w0, w1, 11);
    schedule_rounds4!(w3, w4, w0, w1, w2, 12);
    schedule_rounds4!(w4, w0, w1, w2, w3, 13);
    schedule_rounds4!(w0, w1, w2, w3, w4, 14);
    schedule_rounds4!(w1, w2, w3, w4, w0, 15);

    abef = x86::_mm_add_epi32(abef, abef_save);
    cdgh = x86::_mm_add_epi32(cdgh, cdgh_save);
    shani_unpack_state(abef, cdgh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fips;

    #[test]
    fn abc_block_matches_fips() {
        // The single padded block of "abc".
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 24;
        let want = fips::compress(fips::H0, &block);
        assert_eq!(want[0], 0xba78_16bf);
        assert_eq!(compress_aarch64_models(fips::H0, &block), want);
        assert_eq!(compress_x86_models(fips::H0, &block), want);
    }

    #[test]
    fn state_packing_round_trips() {
        let s = [1, 2, 3, 4, 5, 6, 7, 8];
        let (abef, cdgh) = shani_pack_state(s);
        assert_eq!(x86::view_u32(abef), [6, 5, 2, 1]);
        assert_eq!(x86::view_u32(cdgh), [8, 7, 4, 3]);
        assert_eq!(shani_unpack_state(abef, cdgh), s);
    }
}
