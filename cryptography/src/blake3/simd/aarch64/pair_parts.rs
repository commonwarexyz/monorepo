//! Direct loads for pairs of short messages with fixed part layouts.

use super::{Dup, Words, supported, supports_sha3};
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::aarch64::{
    uint32x4_t, vcombine_u8, vdup_n_u8, vdupq_n_u32, vextq_u32, vld1_u8, vld1q_u8,
    vreinterpretq_u32_u8, vsetq_lane_u32, vzip1q_u32, vzip2q_u32,
};

/// Hash two messages when both have the same supported part layout.
///
/// Each part is loaded within its own bounds. Unsupported layouts and CPUs
/// without the SHA-3 extension use the general pair path.
#[inline]
pub(in crate::blake3::simd) fn hash_pair_parts(
    left: &[&[u8]],
    right: &[&[u8]],
) -> Option<[[u8; OUT_LEN]; 2]> {
    // Direct layouts start with a four-byte index, eight-byte position, or digest.
    if !matches!(left.first(), Some(part) if matches!(part.len(), 4 | 8 | 32)) {
        return None;
    }
    if !supported() || !supports_sha3() {
        return None;
    }
    // SAFETY: The CPU supports NEON and SHA-3. The kernel checks the exact
    // length of every part before loading from it.
    unsafe { hash_pair_parts_sha3(left, right) }
}

#[inline(always)]
unsafe fn pack_rows(left: uint32x4_t, right: uint32x4_t) -> [Dup; 4] {
    // SAFETY: The caller establishes NEON.
    unsafe {
        let low = vzip1q_u32(left, right);
        let high = vzip2q_u32(left, right);
        [
            Dup(vzip1q_u32(low, low)),
            Dup(vzip2q_u32(low, low)),
            Dup(vzip1q_u32(high, high)),
            Dup(vzip2q_u32(high, high)),
        ]
    }
}

#[inline(always)]
unsafe fn block(left: [uint32x4_t; 4], right: [uint32x4_t; 4]) -> [Dup; 16] {
    // SAFETY: The caller establishes NEON.
    unsafe {
        let mut words = [Dup(vdupq_n_u32(0)); 16];
        for (quarter, (left, right)) in left.into_iter().zip(right).enumerate() {
            words[quarter * 4..quarter * 4 + 4].copy_from_slice(&pack_rows(left, right));
        }
        words
    }
}

#[inline(always)]
unsafe fn row16(input: &[u8]) -> uint32x4_t {
    // SAFETY: The caller establishes NEON, and the validated part contains at
    // least 16 bytes at this offset.
    unsafe { vreinterpretq_u32_u8(vld1q_u8(input.as_ptr())) }
}

#[inline(always)]
unsafe fn row8_then8(first: &[u8], second: &[u8]) -> uint32x4_t {
    // SAFETY: The caller establishes NEON, and both validated parts contain
    // at least eight bytes at these offsets.
    unsafe {
        vreinterpretq_u32_u8(vcombine_u8(
            vld1_u8(first.as_ptr()),
            vld1_u8(second.as_ptr()),
        ))
    }
}

#[inline(always)]
unsafe fn row8(input: &[u8]) -> uint32x4_t {
    // SAFETY: The caller establishes NEON, and the validated part contains at
    // least eight bytes at this offset.
    unsafe { vreinterpretq_u32_u8(vcombine_u8(vld1_u8(input.as_ptr()), vdup_n_u8(0))) }
}

#[inline(always)]
const unsafe fn word4(input: &[u8]) -> u32 {
    // SAFETY: The caller validates that this part contains at least four bytes.
    u32::from_le(unsafe { core::ptr::read_unaligned(input.as_ptr().cast::<u32>()) })
}

/// Hash two validated part layouts with the existing duplicated SHA-3 words.
///
/// # Safety
///
/// The caller must establish NEON and SHA-3 availability.
#[target_feature(enable = "neon,sha3")]
unsafe fn hash_pair_parts_sha3(left: &[&[u8]], right: &[&[u8]]) -> Option<[[u8; OUT_LEN]; 2]> {
    let (left_rows, right_rows, tail, len) = match (left, right) {
        ([lp, ld], [rp, rd])
            if lp.len() == 8 && ld.len() == 32 && rp.len() == 8 && rd.len() == 32 =>
        {
            // SAFETY: Both positions are eight bytes and both digests are 32 bytes.
            unsafe {
                let rows = |p: &[u8], d: &[u8]| {
                    [
                        row8_then8(p, d),
                        row16(&d[8..]),
                        row8(&d[24..]),
                        vdupq_n_u32(0),
                    ]
                };
                (rows(lp, ld), rows(rp, rd), None, 40)
            }
        }
        ([ll, lr], [rl, rr])
            if ll.len() == 32 && lr.len() == 32 && rl.len() == 32 && rr.len() == 32 =>
        {
            // SAFETY: Each child digest is 32 bytes.
            unsafe {
                let rows =
                    |l: &[u8], r: &[u8]| [row16(l), row16(&l[16..]), row16(r), row16(&r[16..])];
                (rows(ll, lr), rows(rl, rr), None, 64)
            }
        }
        ([lp, ll, lr], [rp, rl, rr])
            if lp.len() == 8
                && ll.len() == 32
                && lr.len() == 32
                && rp.len() == 8
                && rl.len() == 32
                && rr.len() == 32 =>
        {
            // SAFETY: Both positions are eight bytes and all digests are 32 bytes.
            unsafe {
                let rows = |p: &[u8], l: &[u8], r: &[u8]| {
                    [
                        row8_then8(p, l),
                        row16(&l[8..]),
                        row8_then8(&l[24..], r),
                        row16(&r[8..]),
                    ]
                };
                let zero = vdupq_n_u32(0);
                let tail = |r: &[u8]| [row8(&r[24..]), zero, zero, zero];
                (
                    rows(lp, ll, lr),
                    rows(rp, rl, rr),
                    Some((tail(lr), tail(rr))),
                    72,
                )
            }
        }
        ([li, ld], [ri, rd])
            if li.len() == 4 && ld.len() == 32 && ri.len() == 4 && rd.len() == 32 =>
        {
            // SAFETY: Each index contains four bytes and each digest contains 32 bytes.
            unsafe {
                let zero = vdupq_n_u32(0);
                let rows = |i: &[u8], d: &[u8]| {
                    let head = row16(d);
                    let head = vsetq_lane_u32::<0>(word4(i), vextq_u32::<3>(head, head));
                    [
                        head,
                        row16(&d[12..]),
                        vsetq_lane_u32::<0>(word4(&d[28..]), zero),
                        zero,
                    ]
                };
                (rows(li, ld), rows(ri, rd), None, 36)
            }
        }
        _ => return None,
    };

    // SAFETY: The shape guard established all input extents. This function
    // enables SHA-3 and NEON, and each message is one BLAKE3 chunk.
    unsafe {
        let mut cv = super::super::iv::<Dup, 2>();
        let message = block(left_rows, right_rows);
        let flags = if tail.is_some() {
            super::super::CHUNK_START
        } else {
            super::super::CHUNK_START | super::super::CHUNK_END | super::super::ROOT
        };
        super::super::compress(&mut cv, &message, 0, len.min(BLOCK_LEN), flags);
        if let Some((left_tail, right_tail)) = tail {
            let message = block(left_tail, right_tail);
            super::super::compress(
                &mut cv,
                &message,
                0,
                8,
                super::super::CHUNK_END | super::super::ROOT,
            );
        }
        Some(<Dup as Words<2>>::store(cv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(lengths: &[usize], offset: usize, seed: u8) -> Vec<Box<[u8]>> {
        lengths
            .iter()
            .enumerate()
            .map(|(part, &len)| {
                (0..offset + len)
                    .map(|i| seed.wrapping_add((i * 31 + part * 59) as u8))
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            })
            .collect()
    }

    fn slices(backing: &[Box<[u8]>], offset: usize) -> Vec<&[u8]> {
        backing.iter().map(|part| &part[offset..]).collect()
    }

    #[test]
    fn exact_part_layouts_match_reference_with_unaligned_separate_allocations() {
        if !supported() || !supports_sha3() {
            return;
        }
        for lengths in [[4, 32, 0], [8, 32, 0], [32, 32, 0], [8, 32, 32]] {
            let lengths = if lengths[2] == 0 {
                &lengths[..2]
            } else {
                &lengths[..]
            };
            for offset in 0..16 {
                let left = parts(lengths, offset, 0x21);
                let right = parts(lengths, 15 - offset, 0xa3);
                let left = slices(&left, offset);
                let right = slices(&right, 15 - offset);
                let [left_digest, right_digest] =
                    hash_pair_parts(&left, &right).expect("supported part layout");
                assert_eq!(left_digest, *blake3::hash(&left.concat()).as_bytes());
                assert_eq!(right_digest, *blake3::hash(&right.concat()).as_bytes());
                assert_eq!(
                    hash_pair_parts(&left, &left),
                    Some([left_digest, left_digest]),
                    "aliased inputs"
                );
            }
        }
    }

    #[test]
    fn unsupported_part_layouts_return_none() {
        let bytes = [0u8; 72];
        let pos = &bytes[..8];
        let index = &bytes[..4];
        let digest = &bytes[..32];
        assert_eq!(
            hash_pair_parts(&[index, digest], &[index, &digest[..31]]),
            None
        );
        assert_eq!(hash_pair_parts(&[index, digest], &[pos, digest]), None);
        assert_eq!(
            hash_pair_parts(&[index, digest], &[index, &bytes[..33]]),
            None
        );
        assert_eq!(hash_pair_parts(&[pos, digest], &[pos, &digest[..31]]), None);
        assert_eq!(
            hash_pair_parts(&[pos, digest], &[&bytes[..9], &bytes[..31]]),
            None
        );
        assert_eq!(hash_pair_parts(&[digest, pos], &[digest, pos]), None);
        assert_eq!(
            hash_pair_parts(&[pos, digest, &[]], &[pos, digest, &[]]),
            None
        );
        assert_eq!(
            hash_pair_parts(&[digest, digest], &[&bytes[..31], &bytes[..33]]),
            None
        );
        assert_eq!(
            hash_pair_parts(&[pos, digest, digest], &[pos, &digest[..31], &bytes[..33]]),
            None
        );
        assert_eq!(hash_pair_parts(&[pos], &[pos]), None);
    }
}
