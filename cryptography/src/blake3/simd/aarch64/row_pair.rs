//! Two independent state-row streams with 32-bit SVE2 xor-rotates.

use super::{
    super::{CHUNK_END, CHUNK_START, IV, ROOT},
    pair_parts::{PairRows, Rows, load_parts},
    xar,
};
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::aarch64::*;

/// Mix the same half-G in both messages before advancing their dependencies.
#[inline(always)]
unsafe fn mix<const R: u32, const S: u32>(state: &mut [Rows; 2], message: [uint32x4_t; 2]) {
    // SAFETY: The caller establishes NEON and SVE2.
    unsafe {
        state[0][0] = vaddq_u32(vaddq_u32(state[0][0], message[0]), state[0][1]);
        state[1][0] = vaddq_u32(vaddq_u32(state[1][0], message[1]), state[1][1]);
        state[0][3] = xar::<R>(state[0][3], state[0][0]);
        state[1][3] = xar::<R>(state[1][3], state[1][0]);
        state[0][2] = vaddq_u32(state[0][2], state[0][3]);
        state[1][2] = vaddq_u32(state[1][2], state[1][3]);
        state[0][1] = xar::<S>(state[0][1], state[0][2]);
        state[1][1] = xar::<S>(state[1][1], state[1][2]);
    }
}

/// Align the diagonals as columns while keeping the last-produced row fixed.
#[inline(always)]
unsafe fn diagonalize(state: &mut [Rows; 2]) {
    // SAFETY: The caller establishes NEON.
    unsafe {
        for rows in state {
            rows[0] = vextq_u32::<3>(rows[0], rows[0]);
            rows[2] = vextq_u32::<1>(rows[2], rows[2]);
            rows[3] = vextq_u32::<2>(rows[3], rows[3]);
        }
    }
}

#[inline(always)]
unsafe fn undiagonalize(state: &mut [Rows; 2]) {
    // SAFETY: The caller establishes NEON.
    unsafe {
        for rows in state {
            rows[0] = vextq_u32::<1>(rows[0], rows[0]);
            rows[2] = vextq_u32::<3>(rows[2], rows[2]);
            rows[3] = vextq_u32::<2>(rows[3], rows[3]);
        }
    }
}

#[inline(always)]
unsafe fn round(state: &mut [Rows; 2], message: &[Rows; 2]) {
    // SAFETY: The caller establishes NEON and SVE2.
    unsafe {
        mix::<16, 12>(state, [message[0][0], message[1][0]]);
        mix::<8, 7>(state, [message[0][1], message[1][1]]);
        diagonalize(state);
        mix::<16, 12>(state, [message[0][2], message[1][2]]);
        mix::<8, 7>(state, [message[0][3], message[1][3]]);
        undiagonalize(state);
    }
}

/// Byte indices selecting four little-endian words from a vector table.
const fn indices(words: [u8; 4]) -> [u8; 16] {
    let mut bytes = [0; 16];
    let mut i = 0;
    while i < 16 {
        bytes[i] = words[i / 4] * 4 + (i % 4) as u8;
        i += 1;
    }
    bytes
}

/// Apply the BLAKE3 permutation to the even/odd column/diagonal groups.
#[inline(always)]
unsafe fn permute(message: &mut [Rows; 2]) {
    // SAFETY: The caller establishes NEON. Each index array has sixteen bytes.
    unsafe {
        let i0 = vld1q_u8(indices([1, 5, 7, 2]).as_ptr());
        let i1 = vld1q_u8(indices([3, 10, 0, 15]).as_ptr());
        let i2 = vld1q_u8(indices([8, 0, 7, 9]).as_ptr());
        let i3 = vld1q_u8(indices([5, 10, 2, 4]).as_ptr());
        for words in message {
            let [a, b, c, d] = *words;
            let a = vreinterpretq_u8_u32(a);
            let b = vreinterpretq_u8_u32(b);
            let c = vreinterpretq_u8_u32(c);
            let d = vreinterpretq_u8_u32(d);
            *words = [
                vreinterpretq_u32_u8(vqtbl2q_u8(uint8x16x2_t(a, b), i0)),
                vreinterpretq_u32_u8(vqtbl4q_u8(uint8x16x4_t(a, b, c, d), i1)),
                vreinterpretq_u32_u8(vqtbl3q_u8(uint8x16x3_t(b, c, d), i2)),
                vreinterpretq_u32_u8(vqtbl3q_u8(uint8x16x3_t(b, c, d), i3)),
            ];
        }
    }
}

#[inline(always)]
unsafe fn compress(cv: &mut [[uint32x4_t; 2]; 2], mut message: PairRows, len: usize, flags: u32) {
    // SAFETY: The caller establishes NEON and SVE2. Both constant rows hold
    // four words, and the block length is at most 64.
    unsafe {
        let iv = vld1q_u32(IV.as_ptr());
        let control = vld1q_u32([0, 0, len as u32, flags].as_ptr());
        let mut state = [
            [cv[0][0], cv[0][1], iv, control],
            [cv[1][0], cv[1][1], iv, control],
        ];
        for words in &mut message {
            let [a, b, c, d] = *words;
            let even = vuzp1q_u32(c, d);
            let odd = vuzp2q_u32(c, d);
            *words = [
                vuzp1q_u32(a, b),
                vuzp2q_u32(a, b),
                vextq_u32::<3>(even, even),
                vextq_u32::<3>(odd, odd),
            ];
        }
        round(&mut state, &message);
        macro_rules! next_round {
            () => {{
                permute(&mut message);
                round(&mut state, &message);
            }};
        }
        next_round!();
        next_round!();
        next_round!();
        next_round!();
        next_round!();
        next_round!();
        cv[0] = [
            veorq_u32(state[0][0], state[0][2]),
            veorq_u32(state[0][1], state[0][3]),
        ];
        cv[1] = [
            veorq_u32(state[1][0], state[1][2]),
            veorq_u32(state[1][1], state[1][3]),
        ];
    }
}

/// Compress the final eight bytes of each 72-byte message.
#[inline(always)]
unsafe fn compress_tail(cv: &mut [[uint32x4_t; 2]; 2], message: [uint32x4_t; 2]) {
    // SAFETY: The caller establishes NEON and SVE2. Both constant rows hold
    // four words. Only the low two lanes of each message row are consumed.
    unsafe {
        let iv = vld1q_u32(IV.as_ptr());
        let control = vld1q_u32([0, 0, 8, CHUNK_END | ROOT].as_ptr());
        let mut state = [
            [cv[0][0], cv[0][1], iv, control],
            [cv[1][0], cv[1][1], iv, control],
        ];
        let zero = vdupq_n_u32(0);
        macro_rules! tail_round {
            ($words:ident => [$($row:expr),* $(,)?]) => {{
                let $words = message[0];
                let left = [$($row),*];
                let $words = message[1];
                let right = [$($row),*];
                round(&mut state, &[left, right]);
            }};
        }

        // Only message words zero and one are present. Each round places them
        // in the even/odd column and diagonal groups of the BLAKE3 schedule.
        tail_round!(words => [
            vsetq_lane_u32::<0>(vgetq_lane_u32::<0>(words), zero),
            vsetq_lane_u32::<0>(vgetq_lane_u32::<1>(words), zero),
            zero,
            zero,
        ]);
        tail_round!(words => [
            zero,
            vsetq_lane_u32::<2>(vgetq_lane_u32::<0>(words), zero),
            vsetq_lane_u32::<1>(vgetq_lane_u32::<1>(words), zero),
            zero,
        ]);
        tail_round!(words => [
            zero,
            zero,
            zero,
            vsetq_lane_u32::<2>(
                vgetq_lane_u32::<0>(words),
                vsetq_lane_u32::<0>(vgetq_lane_u32::<1>(words), zero),
            ),
        ]);
        tail_round!(words => [
            zero,
            zero,
            vsetq_lane_u32::<0>(vgetq_lane_u32::<1>(words), zero),
            vsetq_lane_u32::<1>(vgetq_lane_u32::<0>(words), zero),
        ]);
        tail_round!(words => [
            zero,
            zero,
            vsetq_lane_u32::<3>(vgetq_lane_u32::<0>(words), zero),
            vsetq_lane_u32::<3>(vgetq_lane_u32::<1>(words), zero),
        ]);
        tail_round!(words => [
            zero,
            vsetq_lane_u32::<3>(vgetq_lane_u32::<1>(words), zero),
            vsetq_lane_u32::<2>(vgetq_lane_u32::<0>(words), zero),
            zero,
        ]);
        tail_round!(words => [
            vsetq_lane_u32::<2>(vgetq_lane_u32::<1>(words), zero),
            vsetq_lane_u32::<1>(vgetq_lane_u32::<0>(words), zero),
            zero,
            zero,
        ]);
        cv[0] = [
            veorq_u32(state[0][0], state[0][2]),
            veorq_u32(state[0][1], state[0][3]),
        ];
        cv[1] = [
            veorq_u32(state[1][0], state[1][2]),
            veorq_u32(state[1][1], state[1][3]),
        ];
    }
}

/// Hash two exact part layouts with independently scheduled row states.
///
/// # Safety
///
/// The caller must establish NEON and SVE2 availability.
#[target_feature(enable = "neon")]
pub(super) unsafe fn hash_pair_parts(
    left: &[&[u8]],
    right: &[&[u8]],
) -> Option<[[u8; OUT_LEN]; 2]> {
    // SAFETY: NEON is enabled here and the caller establishes SVE2. The
    // loader checks every part's extent before loading any message bytes.
    unsafe {
        let (message, tail, len) = load_parts(left, right)?;
        let mut cv = [[vld1q_u32(IV.as_ptr()), vld1q_u32(IV.as_ptr().add(4))]; 2];
        let flags = if tail.is_some() {
            CHUNK_START
        } else {
            CHUNK_START | CHUNK_END | ROOT
        };
        compress(&mut cv, message, len.min(BLOCK_LEN), flags);
        if let Some(message) = tail {
            compress_tail(&mut cv, [message[0][0], message[1][0]]);
        }
        let mut output = [[0; OUT_LEN]; 2];
        vst1q_u8(output[0].as_mut_ptr(), vreinterpretq_u8_u32(cv[0][0]));
        vst1q_u8(
            output[0].as_mut_ptr().add(16),
            vreinterpretq_u8_u32(cv[0][1]),
        );
        vst1q_u8(output[1].as_mut_ptr(), vreinterpretq_u8_u32(cv[1][0]));
        vst1q_u8(
            output[1].as_mut_ptr().add(16),
            vreinterpretq_u8_u32(cv[1][1]),
        );
        Some(output)
    }
}
