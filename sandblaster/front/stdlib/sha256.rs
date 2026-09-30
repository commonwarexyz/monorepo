//! SHA-256, FIPS 180-4 (August 2015), section by section, written from the standard (the same
//! text as the QMDB fixture's `spec/sha256.rs`, without that crate's links to its own code), and
//! what a collision is. Optional part of the standard library: a crate whose laws or host models
//! hash mounts it on its own (`#[cfg(sandblaster)] #[path = ".../stdlib/sha256.rs"] mod
//! sha256;`), so crates that do not hash never evaluate its examples.
//!
//! The message schedule is computed as FIPS §6.2.2 step 1 defines it, over a sliding window of
//! the 16 words before `W_t` (the form of FIPS §6.2.3's alternative method): each round reads
//! the window, so the definition evaluates in time linear in the rounds.

use sandblaster::prelude::*;

/// A digest (32 bytes).
pub type Digest = [u8; 32];

/// §4.2.2: the first 32 bits of the fractional parts of the cube roots of the first 64 primes.
pub const K: [u32; 64] = [
    0x428a2f98u32, 0x71374491u32, 0xb5c0fbcfu32, 0xe9b5dba5u32,
    0x3956c25bu32, 0x59f111f1u32, 0x923f82a4u32, 0xab1c5ed5u32,
    0xd807aa98u32, 0x12835b01u32, 0x243185beu32, 0x550c7dc3u32,
    0x72be5d74u32, 0x80deb1feu32, 0x9bdc06a7u32, 0xc19bf174u32,
    0xe49b69c1u32, 0xefbe4786u32, 0x0fc19dc6u32, 0x240ca1ccu32,
    0x2de92c6fu32, 0x4a7484aau32, 0x5cb0a9dcu32, 0x76f988dau32,
    0x983e5152u32, 0xa831c66du32, 0xb00327c8u32, 0xbf597fc7u32,
    0xc6e00bf3u32, 0xd5a79147u32, 0x06ca6351u32, 0x14292967u32,
    0x27b70a85u32, 0x2e1b2138u32, 0x4d2c6dfcu32, 0x53380d13u32,
    0x650a7354u32, 0x766a0abbu32, 0x81c2c92eu32, 0x92722c85u32,
    0xa2bfe8a1u32, 0xa81a664bu32, 0xc24b8b70u32, 0xc76c51a3u32,
    0xd192e819u32, 0xd6990624u32, 0xf40e3585u32, 0x106aa070u32,
    0x19a4c116u32, 0x1e376c08u32, 0x2748774cu32, 0x34b0bcb5u32,
    0x391c0cb3u32, 0x4ed8aa4au32, 0x5b9cca4fu32, 0x682e6ff3u32,
    0x748f82eeu32, 0x78a5636fu32, 0x84c87814u32, 0x8cc70208u32,
    0x90befffau32, 0xa4506cebu32, 0xbef9a3f7u32, 0xc67178f2u32,
];

/// §5.3.3: the first 32 bits of the fractional parts of the square roots of the first 8 primes.
pub const H0: [u32; 8] = [
    0x6a09e667u32, 0xbb67ae85u32, 0x3c6ef372u32, 0xa54ff53au32,
    0x510e527fu32, 0x9b05688cu32, 0x1f83d9abu32, 0x5be0cd19u32,
];

// §3.2 and §4.1.2, equations (4.2)-(4.7). Words are 32 bits; `wrapping_add` is addition modulo
// 2^32 and `rotate_right(n)` is ROTR^n.

/// §4.1.2 (4.2): `Ch(x, y, z)`.
#[spec]
#[example(ch(0xF0F0F0F0u32, 0xFF00FF00u32, 0x0F0F0F0Fu32) == 0xFF0FFF0Fu32)]
pub fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
/// §4.1.2 (4.3): `Maj(x, y, z)`.
#[spec]
#[example(maj(0xF0F0F0F0u32, 0xFF00FF00u32, 0x0F0F0F0Fu32) == 0xFF00FF00u32)]
pub fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
/// §4.1.2 (4.4): `Σ0(x)`.
#[spec]
#[example(big_sigma0(0x12345678u32) == 0x66146474u32)]
pub fn big_sigma0(x: u32) -> u32 { x.rotate_right(2u32) ^ x.rotate_right(13u32) ^ x.rotate_right(22u32) }
/// §4.1.2 (4.5): `Σ1(x)`.
#[spec]
#[example(big_sigma1(0x12345678u32) == 0x3561abdau32)]
pub fn big_sigma1(x: u32) -> u32 { x.rotate_right(6u32) ^ x.rotate_right(11u32) ^ x.rotate_right(25u32) }
/// §4.1.2 (4.6): `σ0(x)`.
#[spec]
#[example(small_sigma0(0x12345678u32) == 0xe7fce6eeu32)]
pub fn small_sigma0(x: u32) -> u32 { x.rotate_right(7u32) ^ x.rotate_right(18u32) ^ (x >> 3u32) }
/// §4.1.2 (4.7): `σ1(x)`.
#[spec]
#[example(small_sigma1(0x12345678u32) == 0xa1f78649u32)]
pub fn small_sigma1(x: u32) -> u32 { x.rotate_right(17u32) ^ x.rotate_right(19u32) ^ (x >> 10u32) }

/// §5.2.1, §6.2.2 step 1 for `t < 16`: the block as 16 big-endian words `M_0 … M_15`.
#[spec]
pub fn words(b: [u8; 64]) -> [u32; 16] {
    [
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
        u32::from_be_bytes([b[16], b[17], b[18], b[19]]),
        u32::from_be_bytes([b[20], b[21], b[22], b[23]]),
        u32::from_be_bytes([b[24], b[25], b[26], b[27]]),
        u32::from_be_bytes([b[28], b[29], b[30], b[31]]),
        u32::from_be_bytes([b[32], b[33], b[34], b[35]]),
        u32::from_be_bytes([b[36], b[37], b[38], b[39]]),
        u32::from_be_bytes([b[40], b[41], b[42], b[43]]),
        u32::from_be_bytes([b[44], b[45], b[46], b[47]]),
        u32::from_be_bytes([b[48], b[49], b[50], b[51]]),
        u32::from_be_bytes([b[52], b[53], b[54], b[55]]),
        u32::from_be_bytes([b[56], b[57], b[58], b[59]]),
        u32::from_be_bytes([b[60], b[61], b[62], b[63]]),
    ]
}

/// §6.2.2 step 1 for `t ≥ 16`: `W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}`, from the
/// window `win = [W_{t-16}, …, W_{t-1}]`.
#[spec]
pub fn next_word(win: [u32; 16]) -> u32 {
    small_sigma1(win[14]).wrapping_add(win[9]).wrapping_add(small_sigma0(win[1])).wrapping_add(win[0])
}

/// The window moved on by the word `w`.
#[spec]
pub fn shift_in(win: [u32; 16], w: u32) -> [u32; 16] {
    [win[1], win[2], win[3], win[4], win[5], win[6], win[7], win[8], win[9], win[10], win[11], win[12], win[13], win[14], win[15], w]
}

/// §6.2.2 step 3, one round with the working variables `v = [a, b, c, d, e, f, g, h]`, the
/// constant `k = K_t` and the schedule word `w = W_t`.
#[spec]
pub fn round(v: [u32; 8], k: u32, w: u32) -> [u32; 8] {
    let t1 = v[7].wrapping_add(big_sigma1(v[4])).wrapping_add(ch(v[4], v[5], v[6])).wrapping_add(k).wrapping_add(w);
    let t2 = big_sigma0(v[0]).wrapping_add(maj(v[0], v[1], v[2]));
    [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]]
}

/// §6.2.2 steps 1 and 3 for the rounds `t .. t + n` (`t + n = 64`): `win` holds the block words
/// `M_0 … M_15` while `t < 16`, then `W_{t-16} … W_{t-1}`.
#[spec]
#[decreases(n)]
pub fn rounds(n: Nat, t: Nat, v: [u32; 8], win: [u32; 16]) -> [u32; 8] {
    if n == 0 || t >= 64 {
        v
    } else if t < 16 {
        rounds(n - 1, t + 1, round(v, K[t as usize], win[t as usize]), win)
    } else {
        let w = next_word(win);
        rounds(n - 1, t + 1, round(v, K[t as usize], w), shift_in(win, w))
    }
}

/// §6.2.2: one block compressed into the hash value `h` (step 2, the 64 rounds, step 4). Opaque
/// in proofs: facts about a compression stay one call (`unfold(compress)` reveals the rounds).
#[spec]
#[opaque]
pub fn compress(h: [u32; 8], block: [u8; 64]) -> [u32; 8] {
    let v = rounds(64, 0, h, words(block));
    [
        h[0].wrapping_add(v[0]), h[1].wrapping_add(v[1]), h[2].wrapping_add(v[2]), h[3].wrapping_add(v[3]),
        h[4].wrapping_add(v[4]), h[5].wrapping_add(v[5]), h[6].wrapping_add(v[6]), h[7].wrapping_add(v[7]),
    ]
}

/// §5.1.1: the message, a `1` bit, zeros to 56 bytes mod 64, then its length in bits as a 64-bit
/// big-endian integer. FIPS defines messages shorter than 2^64 bits; beyond that the length is
/// taken mod 2^64, as every implementation does, so `sha256` is total.
#[spec]
pub fn pad(m: Seq<u8>) -> Seq<u8> {
    let zeros = (119 - m.len() % 64) % 64;
    seq![..m, 0x80u8, ..Seq::repeat(0u8, zeros), ..((8 * m.len()) as u64).to_be_bytes()]
}

/// §6.2.2 step 4, the output: `H_0 ‖ … ‖ H_7`, each word big-endian. Opaque in proofs.
#[spec]
#[opaque]
pub fn digest(h: [u32; 8]) -> [u8; 32] {
    seq![..h[0].to_be_bytes(), ..h[1].to_be_bytes(), ..h[2].to_be_bytes(), ..h[3].to_be_bytes(),
         ..h[4].to_be_bytes(), ..h[5].to_be_bytes(), ..h[6].to_be_bytes(), ..h[7].to_be_bytes()].to_array::<32>()
}

/// §6.2 step 2 for each block in turn.
#[spec]
pub fn blocks(h: [u32; 8], bs: Seq<[u8; 64]>) -> [u32; 8] {
    match bs {
        [] => h,
        [b, rest @ ..] => blocks(compress(h, b), rest),
    }
}

/// §6.2: the padded message's blocks compressed in turn from `H0`. Opaque in proofs: laws about
/// hash trees treat a digest as a digest (`unfold(sha256)` reveals the definition). The
/// examples are FIPS 180-4's own (Appendix B.1 and B.2 of the 2002 edition; the NIST
/// "SHA256.pdf" example values) and the digest of the empty message.
#[spec]
#[example(sha256(b"abc") == hex!("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad"))]
#[example(sha256(b"") == hex!("e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855"))]
#[example(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") == hex!("248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1"))]
#[opaque]
pub fn sha256(m: Seq<u8>) -> Digest {
    digest(blocks(H0, pad(m).chunks_exact::<64>()))
}

/// The concatenation of byte strings (`parts[0] ‖ parts[1] ‖ …`), for the slice of slices a
/// one-shot hash API takes.
#[spec]
#[example(concat(&[]) == seq![])]
#[example(concat(&[&[1u8, 2u8], &[], &[3u8]]) == seq![1u8, 2u8, 3u8])]
pub fn concat(parts: &[&[u8]]) -> Seq<u8> {
    match parts {
        [] => seq![],
        [p, rest @ ..] => seq![..p, ..concat(rest)],
    }
}

/// SHA-256 of the concatenation of `parts` (the one-shot hash of a list of byte strings, with no
/// separation between them).
#[spec]
#[example(sha256_parts(&[&[0x61u8, 0x62u8], &[0x63u8]]) == sha256(b"abc"))]
#[example(sha256_parts(&[]) == sha256(b""))]
pub fn sha256_parts(parts: &[&[u8]]) -> Digest {
    sha256(concat(parts))
}

/// A SHA-256 collision: two different messages with one digest. Opaque in proofs, like `sha256`.
/// It is the break predicate of the laws that assume collision resistance, so no example shows
/// it `true`; these show it `false`.
#[spec]
#[example(!collision(None))]
#[example(!collision(Some((seq![1u8], seq![1u8]))))]
#[example(!collision(Some((b"abc", b""))))]
#[opaque]
pub fn collision(c: Option<(Seq<u8>, Seq<u8>)>) -> bool {
    match c {
        Some((x, y)) => x != y && sha256(x) == sha256(y),
        None => false,
    }
}

/// Finding a collision is infeasible. An assumption has no logical content: laws that rely on
/// it are stated so that their failure produces a `collision`, and say so (DESIGN §15.13).
#[spec]
#[assumption(class = computational, cite = "SHA-256 collision resistance; NIST SP 800-107 Rev. 1, §4.1")]
pub fn collision_resistance() {}
