//! Eight-lane SHA-512 for AVX-512F: lane `i` of each 512-bit register holds message `i`'s copy of
//! one state or message-schedule word, so every instruction advances eight independent hashes.

use super::{
    DIGEST_LENGTH, Digest,
    padding::{IV, K, block, block_count},
};
use core::arch::x86_64::*;
use sha2::block_api::compress512;

/// Messages hashed per [`hash`] call.
pub(super) const LANES: usize = 8;

/// Hashes `messages` in lockstep, one block per lane per [`compress`], masking each lane out once
/// its blocks run out. Once only the longest message has blocks left, [`compress512`] finishes
/// it one lane wide. Lane `i` of the result is the digest of `messages[i]`, and lanes past
/// `messages.len()` are zero.
///
/// `messages` must hold at most [`LANES`] messages.
#[target_feature(enable = "avx512f")]
pub(super) fn hash(messages: &[&[u8]]) -> [Digest; LANES] {
    let mut counts = [0usize; LANES];
    for (count, message) in counts.iter_mut().zip(messages) {
        *count = block_count(message.len());
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
        for (lane, message) in messages.iter().enumerate() {
            if index < counts[lane] {
                active |= 1 << lane;
                let block = block(message, index);
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
    if let Some(message) = messages.get(longest) {
        let mut tail = [0u64; 8];
        for (word, row) in tail.iter_mut().zip(&rows) {
            *word = row[longest];
        }
        for index in shared..counts[longest] {
            compress512(&mut tail, &[block(message, index)]);
        }
        for (row, word) in rows.iter_mut().zip(tail) {
            row[longest] = word;
        }
    }
    let mut out = [Digest([0u8; DIGEST_LENGTH]); LANES];
    for (lane, digest) in out.iter_mut().enumerate().take(messages.len()) {
        for (bytes, row) in digest.0.as_chunks_mut::<8>().0.iter_mut().zip(&rows) {
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
