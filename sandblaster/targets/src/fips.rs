//! Plain FIPS 180-4 SHA-256 (the portable reference).
//!
//! This is the reference formulation that DESIGN.md §9.7 names as
//! `sha256::compress`: the functions of FIPS 180-4 §4.1.2, the constants of
//! §4.2.2, the message schedule and compression of §6.2.2, written without
//! any cleverness (no merged Ch/Maj forms, no precomputed `W + K`). The
//! hardware models are validated against it ([`crate::consistency`]), and the
//! evidence records use [`sha256`] to hash model source text.
#![forbid(unsafe_code)]
// Loops index lanes explicitly to mirror the vendor pseudocode.
#![allow(clippy::needless_range_loop)]

/// The SHA-256 round constants `K_0 .. K_63` (FIPS 180-4 §4.2.2).
pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The initial hash value `H^(0)` (FIPS 180-4 §5.3.3).
pub const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// `Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)` (FIPS 180-4 (4.2)).
pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// `Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)` (FIPS 180-4 (4.3)).
pub fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// `Σ0(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)` (FIPS 180-4 (4.4)).
pub fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// `Σ1(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)` (FIPS 180-4 (4.5)).
pub fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// `σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)` (FIPS 180-4 (4.6)).
pub fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// `σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)` (FIPS 180-4 (4.7)).
pub fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// One SHA-256 round (FIPS 180-4 §6.2.2 step 3) on the working variables
/// `[a, b, c, d, e, f, g, h]`, taking the round's `K_t + W_t` as one word `kw`
/// (addition mod 2^32 is associative and commutative, so this is the same
/// round; the hardware instructions consume exactly this sum).
pub fn round(s: [u32; 8], kw: u32) -> [u32; 8] {
    let [a, b, c, d, e, f, g, h] = s;
    let t1 = h
        .wrapping_add(big_sigma1(e))
        .wrapping_add(ch(e, f, g))
        .wrapping_add(kw);
    let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
    [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g]
}

/// The big-endian message words `M_0 .. M_15` of a block (FIPS 180-4 §5.2.1).
pub fn block_words(block: &[u8; 64]) -> [u32; 16] {
    let mut m = [0u32; 16];
    for (t, w) in m.iter_mut().enumerate() {
        *w = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
    }
    m
}

/// One message-schedule step (FIPS 180-4 §6.2.2 step 1, `16 ≤ t ≤ 63`):
/// `W_t = σ1(W_{t−2}) + W_{t−7} + σ0(W_{t−15}) + W_{t−16}`.
pub fn schedule_step(w_tm2: u32, w_tm7: u32, w_tm15: u32, w_tm16: u32) -> u32 {
    small_sigma1(w_tm2)
        .wrapping_add(w_tm7)
        .wrapping_add(small_sigma0(w_tm15))
        .wrapping_add(w_tm16)
}

/// The full message schedule `W_0 .. W_63` of a block.
pub fn schedule(block: &[u8; 64]) -> [u32; 64] {
    let m = block_words(block);
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(&m);
    for t in 16..64 {
        w[t] = schedule_step(w[t - 2], w[t - 7], w[t - 15], w[t - 16]);
    }
    w
}

/// The SHA-256 compression function (FIPS 180-4 §6.2.2 steps 1–4) on one
/// 64-byte block.
pub fn compress(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let w = schedule(block);
    let mut s = state;
    for t in 0..64 {
        s = round(s, K[t].wrapping_add(w[t]));
    }
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = state[i].wrapping_add(s[i]);
    }
    out
}

/// SHA-256 of a byte string (FIPS 180-4 §5.1.1 padding + §6.2).
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let (blocks, rest) = msg.as_chunks::<64>();
    for block in blocks {
        state = compress(state, block);
    }
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let tail_len = if rest.len() < 56 { 64 } else { 128 };
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..tail_len].as_chunks::<64>().0 {
        state = compress(state, block);
    }
    let mut out = [0u8; 32];
    for (i, w) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// Lower-case hexadecimal encoding.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        // FIPS 180-4 examples (NIST CSRC "SHA256.pdf") and the empty string.
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&million_a)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn padding_boundaries() {
        // 55, 56, 63, 64 byte messages exercise both padding shapes; compare
        // against a from-scratch padding computation via `compress`.
        for len in [55usize, 56, 57, 63, 64, 65, 119, 120] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let mut padded = msg.clone();
            padded.push(0x80);
            while padded.len() % 64 != 56 {
                padded.push(0);
            }
            padded.extend_from_slice(&((len as u64) * 8).to_be_bytes());
            let mut state = H0;
            for c in padded.as_chunks::<64>().0 {
                state = compress(state, c);
            }
            let mut want = [0u8; 32];
            for (i, w) in state.iter().enumerate() {
                want[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
            }
            assert_eq!(sha256(&msg), want, "len {len}");
        }
    }
}
