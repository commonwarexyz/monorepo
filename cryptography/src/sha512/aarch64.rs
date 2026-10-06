//! Two-lane SHA-512 for the Armv8.2 SHA-512 instructions. Each round of a hash depends on the
//! previous one, so interleaving the rounds of two independent messages hides the instructions'
//! latency.

use super::{
    DIGEST_LENGTH, Digest,
    padding::{BLOCK_LENGTH, IV, K, block, block_count},
};
use core::arch::aarch64::*;
use sha2::block_api::compress512;

/// Messages hashed per [`hash`] call.
pub(super) const LANES: usize = 2;

/// Hashes both messages over the blocks they share, interleaving their rounds, then finishes the
/// longer message's remaining blocks alone with [`compress512`]. Lane `i` of the result is the
/// digest of `messages[i]`.
#[target_feature(enable = "sha3")]
pub(super) fn hash(messages: &[&[u8]; LANES]) -> [Digest; LANES] {
    let counts = [
        block_count(messages[0].len()),
        block_count(messages[1].len()),
    ];
    let shared = counts[0].min(counts[1]);
    let mut state = [IV; LANES];
    for index in 0..shared {
        compress(
            &mut state,
            &[block(messages[0], index), block(messages[1], index)],
        );
    }

    // At most one message has blocks past `shared`, and it finishes them one lane wide.
    for ((words, message), count) in state.iter_mut().zip(messages).zip(counts) {
        for index in shared..count {
            compress512(words, &[block(message, index)]);
        }
    }

    // Each digest is its state's words in big-endian order.
    let mut out = [Digest([0; DIGEST_LENGTH]); LANES];
    for (digest, words) in out.iter_mut().zip(state) {
        for (bytes, word) in digest.0.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *bytes = word.to_be_bytes();
        }
    }
    out
}

/// Compresses one block into each state (FIPS 180-4, section 6.4.2). Each state occupies four
/// registers of word pairs, and each message schedule a ring of eight registers holding
/// `W[t-16..t]` two words apiece.
#[target_feature(enable = "sha3")]
fn compress(state: &mut [[u64; 8]; LANES], blocks: &[[u8; BLOCK_LENGTH]; LANES]) {
    // Load each state as word pairs and each block as big-endian word pairs.
    let mut s = [[vdupq_n_u64(0); 4]; LANES];
    let mut w = [[vdupq_n_u64(0); 8]; LANES];
    for lane in 0..LANES {
        for (reg, words) in s[lane].iter_mut().zip(state[lane].as_chunks::<2>().0) {
            // SAFETY: Each source contains two u64 words; vector loads permit unaligned pointers.
            *reg = unsafe { vld1q_u64(words.as_ptr()) };
        }
        for (reg, bytes) in w[lane].iter_mut().zip(blocks[lane].as_chunks::<16>().0) {
            // SAFETY: Each source contains sixteen bytes; vector loads permit unaligned pointers.
            let bytes = unsafe { vld1q_u8(bytes.as_ptr()) };
            *reg = vreinterpretq_u64_u8(vrev64q_u8(bytes));
        }
    }

    // Each expansion runs sixteen rounds, two per step and one step per schedule register, with
    // literal ring indices so both lanes' schedules and states stay in registers. From round 16 on,
    // a step first replaces its schedule register, holding W[t-16] and W[t-15], with W[t] and
    // W[t+1]. SHA512H then combines the (g, h) pair and the step's K + W with (d, e, f, g) into
    // both rounds' T1 sums, and SHA512H2 adds the T2 sums from (a, b, c), leaving the new (a, b)
    // pair in (g, h)'s register. The (c, d) pair plus the T1 sums becomes the new (e, f) pair,
    // while the old (a, b) and (e, f) pairs become (c, d) and (g, h) in place, so the roles of the
    // four state registers rotate by one each step.
    macro_rules! rounds {
        ($k:expr, $schedule:expr) => {
            rounds!(@ $k, $schedule, 0 1 2 3 4 5 6 7)
        };
        (@ $k:expr, $schedule:expr, $($j:literal)*) => {$(
            if $schedule {
                for words in &mut w {
                    words[$j] = vsha512su1q_u64(
                        vsha512su0q_u64(words[$j], words[($j + 1) % 8]),
                        words[($j + 7) % 8],
                        vextq_u64::<1>(words[($j + 4) % 8], words[($j + 5) % 8]),
                    );
                }
            }
            // SAFETY: Every constants chunk contains sixteen words and j is at most seven.
            let k = unsafe { vld1q_u64($k.as_ptr().add(2 * $j)) };
            let kw0 = vaddq_u64(w[0][$j], k);
            let kw1 = vaddq_u64(w[1][$j], k);
            let sum0 = vaddq_u64(vextq_u64::<1>(kw0, kw0), s[0][(7 - $j) % 4]);
            let sum1 = vaddq_u64(vextq_u64::<1>(kw1, kw1), s[1][(7 - $j) % 4]);
            let t0 = vsha512hq_u64(
                sum0,
                vextq_u64::<1>(s[0][(6 - $j % 4) % 4], s[0][(7 - $j) % 4]),
                vextq_u64::<1>(s[0][(5 - $j % 4) % 4], s[0][(6 - $j % 4) % 4]),
            );
            let t1 = vsha512hq_u64(
                sum1,
                vextq_u64::<1>(s[1][(6 - $j % 4) % 4], s[1][(7 - $j) % 4]),
                vextq_u64::<1>(s[1][(5 - $j % 4) % 4], s[1][(6 - $j % 4) % 4]),
            );
            s[0][(7 - $j) % 4] = vsha512h2q_u64(
                t0, s[0][(5 - $j % 4) % 4], s[0][(4 - $j % 4) % 4],
            );
            s[1][(7 - $j) % 4] = vsha512h2q_u64(
                t1, s[1][(5 - $j % 4) % 4], s[1][(4 - $j % 4) % 4],
            );
            s[0][(5 - $j % 4) % 4] = vaddq_u64(s[0][(5 - $j % 4) % 4], t0);
            s[1][(5 - $j % 4) % 4] = vaddq_u64(s[1][(5 - $j % 4) % 4], t1);
        )*};
    }
    let (chunks, _) = K.as_chunks::<16>();
    rounds!(chunks[0], false);
    for k in &chunks[1..] {
        rounds!(k, true);
    }

    // Add each compressed working state into its input state.
    for (words, working) in state.iter_mut().zip(s) {
        for (pair, reg) in words.as_chunks_mut::<2>().0.iter_mut().zip(working) {
            // SAFETY: Each destination contains two u64 words; loads and stores permit unaligned
            // pointers, and the same pair is read before it is overwritten.
            unsafe { vst1q_u64(pair.as_mut_ptr(), vaddq_u64(vld1q_u64(pair.as_ptr()), reg)) };
        }
    }
}
