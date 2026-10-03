//! The AVX-512 hasher: lane `i` of each 512-bit register holds message `i`'s copy of one SHA-512
//! state or message-schedule word, so every instruction advances eight independent hashes.

use super::LANES;
use core::arch::x86_64::*;
use sha2::block_api::compress512;

/// SHA-512 round constants (FIPS 180-4, section 4.2.3).
#[rustfmt::skip]
const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// SHA-512 initial hash value (FIPS 180-4, section 5.3.5).
#[rustfmt::skip]
const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// The AVX-512 hasher token.
///
/// The private field ensures this can only be constructed after checking the required CPU
/// features with [`available`].
#[derive(Clone, Copy)]
pub(super) struct Hasher(());

/// Feature set this hasher requires: AVX-512F for the 512-bit rotates, ternary logic, and masked
/// adds, and AVX-512 IFMA so it runs exactly where the AVX-512 curve backend runs.
fn available() -> bool {
    is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512ifma")
}

impl Hasher {
    /// Constructs the hasher if the required CPU features are available.
    pub(super) fn new() -> Option<Self> {
        available().then_some(Self(()))
    }

    /// Returns `SHA-512(parts[0] || parts[1] || parts[2])` for each `parts` in `messages`, in
    /// order. Entries past `messages.len()` are zero.
    ///
    /// `messages` must hold at most [`LANES`] messages.
    pub(super) fn digest(self, messages: &[[&[u8]; 3]]) -> [[u8; 64]; LANES] {
        // SAFETY: constructing `self` confirmed AVX-512F support.
        unsafe { digest(messages) }
    }
}

/// The number of 128-byte blocks in the padded encoding of a `len`-byte message: the message,
/// one `0x80` byte, zeros, and the 16-byte bit length.
const fn blocks(len: usize) -> usize {
    len / 128 + if len % 128 < 112 { 1 } else { 2 }
}

/// Block `index` of the padded encoding of `parts[0] || parts[1] || parts[2]` (`len` bytes in
/// total).
///
/// Always inlined: an outlined call returns the block through memory, and the caller's wide
/// loads of it stall on store forwarding.
#[inline(always)]
fn block(parts: &[&[u8]; 3], len: usize, index: usize) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    let start = index * 128;
    let end = start + 128;
    let mut offset = 0;
    for part in parts {
        let lo = offset.max(start);
        let hi = (offset + part.len()).min(end);
        if lo < hi {
            bytes[lo - start..hi - start].copy_from_slice(&part[lo - offset..hi - offset]);
        }
        offset += part.len();
    }
    if (start..end).contains(&len) {
        bytes[len - start] = 0x80;
    }
    if index + 1 == blocks(len) {
        bytes[112..].copy_from_slice(&(len as u128 * 8).to_be_bytes());
    }
    bytes
}

/// Hashes the messages in lockstep, one block per lane per [`compress`], masking each lane out
/// once its blocks run out. Once only the longest message has blocks left, [`compress512`]
/// finishes it one lane wide.
#[target_feature(enable = "avx512f")]
fn digest(messages: &[[&[u8]; 3]]) -> [[u8; 64]; LANES] {
    let mut lens = [0usize; LANES];
    let mut counts = [0usize; LANES];
    for ((len, count), parts) in lens.iter_mut().zip(&mut counts).zip(messages) {
        *len = parts.iter().map(|part| part.len()).sum();
        *count = blocks(*len);
    }
    let mut longest = 0;
    for lane in 1..LANES {
        if counts[lane] > counts[longest] {
            longest = lane;
        }
    }
    let shared = (0..LANES)
        .filter(|&lane| lane != longest)
        .map(|lane| counts[lane])
        .max()
        .unwrap_or(0);

    let mut state = [_mm512_setzero_si512(); 8];
    for (reg, word) in state.iter_mut().zip(IV) {
        *reg = _mm512_set1_epi64(word as i64);
    }
    let mut words = [[0u64; LANES]; 16];
    for index in 0..shared {
        let mut active: __mmask8 = 0;
        for (lane, parts) in messages.iter().enumerate() {
            if index < counts[lane] {
                active |= 1 << lane;
                let block = block(parts, lens[lane], index);
                for (row, chunk) in words.iter_mut().zip(block.as_chunks::<8>().0) {
                    row[lane] = u64::from_be_bytes(*chunk);
                }
            }
        }
        compress(&mut state, &words, active);
    }

    let mut rows = [[0u64; LANES]; 8];
    for (row, reg) in rows.iter_mut().zip(state) {
        // SAFETY: `row` is `[u64; 8]`, exactly one zmm register's worth of packed u64 lanes, and
        // `storeu` places no alignment requirement on the destination.
        unsafe { _mm512_storeu_si512(row.as_mut_ptr().cast(), reg) };
    }
    if let Some(parts) = messages.get(longest) {
        let mut tail = [0u64; 8];
        for (word, row) in tail.iter_mut().zip(&rows) {
            *word = row[longest];
        }
        for index in shared..counts[longest] {
            compress512(&mut tail, &[block(parts, lens[longest], index)]);
        }
        for (row, word) in rows.iter_mut().zip(tail) {
            row[longest] = word;
        }
    }
    let mut out = [[0u8; 64]; LANES];
    for (lane, digest) in out.iter_mut().enumerate().take(messages.len()) {
        for (bytes, row) in digest.as_chunks_mut::<8>().0.iter_mut().zip(&rows) {
            *bytes = row[lane].to_be_bytes();
        }
    }
    out
}

/// `a ^ b ^ c`.
#[target_feature(enable = "avx512f")]
fn xor3(a: __m512i, b: __m512i, c: __m512i) -> __m512i {
    _mm512_ternarylogic_epi64::<0x96>(a, b, c)
}

/// One SHA-512 round (FIPS 180-4, section 6.4.2, step 3) on `[a, b, c, d, e, f, g, h]`, with
/// `kw = K[t] + W[t]`.
#[target_feature(enable = "avx512f")]
fn round(s: [__m512i; 8], kw: __m512i) -> [__m512i; 8] {
    let [a, b, c, d, e, f, g, h] = s;
    let sigma1 = xor3(
        _mm512_ror_epi64::<14>(e),
        _mm512_ror_epi64::<18>(e),
        _mm512_ror_epi64::<41>(e),
    );
    // Ch(e, f, g) = (e & f) ^ (!e & g).
    let ch = _mm512_ternarylogic_epi64::<0xca>(e, f, g);
    let t1 = _mm512_add_epi64(_mm512_add_epi64(h, kw), _mm512_add_epi64(sigma1, ch));
    let sigma0 = xor3(
        _mm512_ror_epi64::<28>(a),
        _mm512_ror_epi64::<34>(a),
        _mm512_ror_epi64::<39>(a),
    );
    // Maj(a, b, c) = (a & b) ^ (a & c) ^ (b & c).
    let maj = _mm512_ternarylogic_epi64::<0xe8>(a, b, c);
    let t2 = _mm512_add_epi64(sigma0, maj);
    [
        _mm512_add_epi64(t1, t2),
        a,
        b,
        c,
        _mm512_add_epi64(d, t1),
        e,
        f,
        g,
    ]
}

/// Replaces `w[j]`, holding `W[t-16]`, with `W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]`
/// (FIPS 180-4, section 6.4.2, step 1), where `w` holds `W[t-16..t]` with `W[u]` at `w[u % 16]`.
#[target_feature(enable = "avx512f")]
fn schedule(w: &mut [__m512i; 16], j: usize) {
    let w15 = w[(j + 1) % 16];
    let w2 = w[(j + 14) % 16];
    let s0 = xor3(
        _mm512_ror_epi64::<1>(w15),
        _mm512_ror_epi64::<8>(w15),
        _mm512_srli_epi64::<7>(w15),
    );
    let s1 = xor3(
        _mm512_ror_epi64::<19>(w2),
        _mm512_ror_epi64::<61>(w2),
        _mm512_srli_epi64::<6>(w2),
    );
    w[j] = _mm512_add_epi64(
        _mm512_add_epi64(w[j], s0),
        _mm512_add_epi64(w[(j + 9) % 16], s1),
    );
}

/// Compresses one block per lane (`words[j][lane]` is word `j` of lane `lane`'s block) into
/// `state`, updating only the lanes set in `active`.
#[target_feature(enable = "avx512f")]
fn compress(state: &mut [__m512i; 8], words: &[[u64; LANES]; 16], active: __mmask8) {
    let mut w = [_mm512_setzero_si512(); 16];
    for (reg, row) in w.iter_mut().zip(words) {
        // SAFETY: `row` is `[u64; 8]`, exactly one zmm register's worth of packed u64 lanes, and
        // `loadu` places no alignment requirement on the source.
        *reg = unsafe { _mm512_loadu_si512(row.as_ptr().cast()) };
    }
    let mut s = *state;

    // Sixteen rounds with literal ring indices, so the schedule stays in registers.
    macro_rules! rounds {
        ($k:expr, $schedule:expr) => {
            rounds!(@ $k, $schedule, 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
        };
        (@ $k:expr, $schedule:expr, $($j:literal)*) => {$(
            if $schedule {
                schedule(&mut w, $j);
            }
            s = round(s, _mm512_add_epi64(w[$j], _mm512_set1_epi64($k[$j] as i64)));
        )*};
    }
    let (chunks, _) = K.as_chunks::<16>();
    rounds!(chunks[0], false);
    for k in &chunks[1..] {
        rounds!(k, true);
    }

    for (reg, working) in state.iter_mut().zip(s) {
        *reg = _mm512_mask_add_epi64(*reg, active, *reg, working);
    }
}
