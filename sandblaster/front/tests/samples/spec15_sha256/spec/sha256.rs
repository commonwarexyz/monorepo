//! FIPS 180-4 (SHA-256) for one-block messages, section by section: the
//! reference semantics the implementation in `../sha.rs` refines. Every
//! function here is a spec function (`#[spec]` module, DESIGN.md §15.1);
//! nothing refers to the implementation.

/// §4.2.2: the first 32 bits of the fractional parts of the cube roots of
/// the first 64 primes.
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

/// §5.3.3: the initial hash value.
pub const H0: [u32; 8] = [
    0x6a09e667u32, 0xbb67ae85u32, 0x3c6ef372u32, 0xa54ff53au32,
    0x510e527fu32, 0x9b05688cu32, 0x1f83d9abu32, 0x5be0cd19u32,
];

/// §4.1.2 (4.2)
pub fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
/// §4.1.2 (4.3)
pub fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
/// §4.1.2 (4.4)
pub fn big_sigma0(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22) }
/// §4.1.2 (4.5)
pub fn big_sigma1(x: u32) -> u32 { x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25) }
/// §4.1.2 (4.6)
pub fn small_sigma0(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3u32) }
/// §4.1.2 (4.7)
pub fn small_sigma1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10u32) }

/// §5.2.1, §6.2.2 step 1 for `t < 16`: the block as 16 big-endian words
/// `M_0 .. M_15`.
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

/// §6.2.2 step 1 for `t ≥ 16`: `W_t` from the 16 words before it,
/// `win = [W_(t-16), …, W_(t-1)]`.
pub fn next_word(win: [u32; 16]) -> u32 {
    small_sigma1(win[14]).wrapping_add(win[9]).wrapping_add(small_sigma0(win[1])).wrapping_add(win[0])
}

/// The window moved by one word.
pub fn shift_in(win: [u32; 16], w: u32) -> [u32; 16] {
    [win[1], win[2], win[3], win[4], win[5], win[6], win[7], win[8], win[9], win[10], win[11], win[12], win[13], win[14], win[15], w]
}

/// §6.2.2 step 3, one round `t` with the working variables
/// `v = [a, b, c, d, e, f, g, h]` and the schedule word `w = W_t`.
pub fn round(v: [u32; 8], k: u32, w: u32) -> [u32; 8] {
    let t1 = v[7].wrapping_add(big_sigma1(v[4])).wrapping_add(ch(v[4], v[5], v[6])).wrapping_add(k).wrapping_add(w);
    let t2 = big_sigma0(v[0]).wrapping_add(maj(v[0], v[1], v[2]));
    [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]]
}

/// §6.2.2 steps 1 and 3 for rounds `t .. t + n` (`t + n = 64`): `win` holds
/// the block words `M_0 .. M_15` for `t < 16`, then `W_(t-16) .. W_(t-1)`.
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

/// §6.2.2: the compression of one block into the hash value `h` (step 2,
/// the 64 rounds, step 4). Known answer: the block `00 01 … 3f` from the
/// initial hash value, computed by an independent Python implementation of
/// FIPS 180-4 that agrees with OpenSSL (`hashlib`) on every message length
/// from 0 to 129 bytes (every byte of the block is distinct, so each of
/// the 16 words and each byte order is checked).
#[example(compress(H0, [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]) == [0xfc99a2dfu32, 0x88f42a7a, 0x7bb9d180, 0x33cdc6a2, 0x0256755f, 0x9d5b9a50, 0x44a9cc31, 0x5abe84a7])]
pub fn compress(h: [u32; 8], block: [u8; 64]) -> [u32; 8] {
    let v = rounds(64, 0, h, words(block));
    [
        h[0].wrapping_add(v[0]), h[1].wrapping_add(v[1]), h[2].wrapping_add(v[2]), h[3].wrapping_add(v[3]),
        h[4].wrapping_add(v[4]), h[5].wrapping_add(v[5]), h[6].wrapping_add(v[6]), h[7].wrapping_add(v[7]),
    ]
}

/// §5.1.1: byte `i` of the padded message `m` (`m.len() ≤ 55`: one
/// block): the message, the bit `1` (`0x80`), zeros, and the 64-bit
/// big-endian bit length `ℓ = 8·len(m) ≤ 440` (only its last two bytes are
/// non-zero on this domain).
pub fn pad_byte(m: Seq<u8>, i: Nat) -> u8 {
    let l = 8 * m.len();
    if i < m.len() { m[i] } else if i == m.len() { 0x80 } else if i == 62 { (l / 256) as u8 } else if i == 63 { (l % 256) as u8 } else { 0 }
}

/// The padded one-block message.
pub fn block1(m: Seq<u8>) -> [u8; 64] {
    [
        pad_byte(m, 0), pad_byte(m, 1), pad_byte(m, 2), pad_byte(m, 3), pad_byte(m, 4), pad_byte(m, 5), pad_byte(m, 6), pad_byte(m, 7),
        pad_byte(m, 8), pad_byte(m, 9), pad_byte(m, 10), pad_byte(m, 11), pad_byte(m, 12), pad_byte(m, 13), pad_byte(m, 14), pad_byte(m, 15),
        pad_byte(m, 16), pad_byte(m, 17), pad_byte(m, 18), pad_byte(m, 19), pad_byte(m, 20), pad_byte(m, 21), pad_byte(m, 22), pad_byte(m, 23),
        pad_byte(m, 24), pad_byte(m, 25), pad_byte(m, 26), pad_byte(m, 27), pad_byte(m, 28), pad_byte(m, 29), pad_byte(m, 30), pad_byte(m, 31),
        pad_byte(m, 32), pad_byte(m, 33), pad_byte(m, 34), pad_byte(m, 35), pad_byte(m, 36), pad_byte(m, 37), pad_byte(m, 38), pad_byte(m, 39),
        pad_byte(m, 40), pad_byte(m, 41), pad_byte(m, 42), pad_byte(m, 43), pad_byte(m, 44), pad_byte(m, 45), pad_byte(m, 46), pad_byte(m, 47),
        pad_byte(m, 48), pad_byte(m, 49), pad_byte(m, 50), pad_byte(m, 51), pad_byte(m, 52), pad_byte(m, 53), pad_byte(m, 54), pad_byte(m, 55),
        pad_byte(m, 56), pad_byte(m, 57), pad_byte(m, 58), pad_byte(m, 59), pad_byte(m, 60), pad_byte(m, 61), pad_byte(m, 62), pad_byte(m, 63),
    ]
}

/// §6.2.2 step 4 output: `H_0 ‖ … ‖ H_7`, big-endian.
pub fn digest(h: [u32; 8]) -> [u8; 32] {
    seq![..h[0].to_be_bytes(), ..h[1].to_be_bytes(), ..h[2].to_be_bytes(), ..h[3].to_be_bytes(),
         ..h[4].to_be_bytes(), ..h[5].to_be_bytes(), ..h[6].to_be_bytes(), ..h[7].to_be_bytes()].to_array::<32>()
}

/// SHA-256 of a message of at most 55 bytes; `None` beyond one block.
#[example(hash1(b"abc") == Some(hex!("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad")))]
#[example(hash1(seq![]) == Some(hex!("e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855")))]
#[example(hash1(Seq::repeat(0u8, 56)) == None)]
pub fn hash1(m: Seq<u8>) -> Option<[u8; 32]> {
    if m.len() > 55 { None } else { Some(digest(compress(H0, block1(m)))) }
}

/// The CAVP short-message records: `Len` bits of `Msg` hash to `MD`. A
/// wrong digest is rejected (the empty message does not hash to zero).
#[example(!cavp(0, seq![], [0u8; 32]))]
#[examples(file = "../vectors/sha256_short.rsp", format = "cavp", provenance = independent)]
pub fn cavp(len: Nat, msg: Seq<u8>, md: [u8; 32]) -> bool {
    hash1(msg.take(len / 8)) == Some(md)
}
