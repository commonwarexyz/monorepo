//! Direct loads for pairs of short messages with fixed part layouts.

use super::{Dup, Words, supported, supports_sha3, supports_sve2};
use crate::blake3::simd::{CHUNK_END, CHUNK_START, ROOT, compress, iv};
use blake3::{BLOCK_LEN, OUT_LEN};
use core::arch::aarch64::{
    uint32x4_t, vcombine_u8, vdup_n_u8, vdupq_n_u32, vextq_u32, vld1_u8, vld1q_u8,
    vreinterpretq_u32_u8, vsetq_lane_u32, vzip1q_u32, vzip2q_u32,
};

/// Hash two messages when both have the same supported part layout.
///
/// Each part is loaded within its own bounds. Returns `None` for unsupported
/// layouts and on CPUs supporting neither SVE2 nor the SHA-3 extension.
#[inline]
pub(in crate::blake3::simd) fn hash_pair_parts(
    left: &[&[u8]],
    right: &[&[u8]],
) -> Option<[[u8; OUT_LEN]; 2]> {
    // Contiguous messages of a layout length load as that layout's fields.
    if let ([left], [right]) = (left, right) {
        return match (left.len(), right.len()) {
            (36, 36) => hash_pair_parts(&[&left[..4], &left[4..]], &[&right[..4], &right[4..]]),
            (40, 40) => hash_pair_parts(&[&left[..8], &left[8..]], &[&right[..8], &right[8..]]),
            (64, 64) => hash_pair_parts(&[&left[..32], &left[32..]], &[&right[..32], &right[32..]]),
            (72, 72) => hash_pair_parts(
                &[&left[..8], &left[8..40], &left[40..]],
                &[&right[..8], &right[8..40], &right[40..]],
            ),
            _ => None,
        };
    }

    // Direct layouts start with a four-byte index, eight-byte position, or digest.
    if !matches!(left.first(), Some(part) if matches!(part.len(), 4 | 8 | 32)) {
        return None;
    }
    if !supported() {
        return None;
    }
    if supports_sve2() {
        // SAFETY: NEON and SVE2 availability were established above.
        return unsafe { super::row_pair::hash_pair_parts(left, right) };
    }
    if !supports_sha3() {
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

pub(super) type Rows = [uint32x4_t; 4];
pub(super) type PairRows = [Rows; 2];

#[inline(always)]
unsafe fn leaf_rows(p: &[u8], d: &[u8]) -> Rows {
    // SAFETY: The caller validates an eight-byte position and 32-byte digest
    // and establishes NEON.
    unsafe {
        [
            row8_then8(p, d),
            row16(&d[8..]),
            row8(&d[24..]),
            vdupq_n_u32(0),
        ]
    }
}

#[inline(always)]
unsafe fn child_rows(l: &[u8], r: &[u8]) -> Rows {
    // SAFETY: The caller validates two 32-byte digests and establishes NEON.
    unsafe { [row16(l), row16(&l[16..]), row16(r), row16(&r[16..])] }
}

#[inline(always)]
unsafe fn node_rows(p: &[u8], l: &[u8], r: &[u8]) -> Rows {
    // SAFETY: The caller validates an eight-byte position and two 32-byte
    // digests and establishes NEON.
    unsafe {
        [
            row8_then8(p, l),
            row16(&l[8..]),
            row8_then8(&l[24..], r),
            row16(&r[8..]),
        ]
    }
}

#[inline(always)]
unsafe fn indexed_rows(i: &[u8], d: &[u8]) -> Rows {
    // SAFETY: The caller validates a four-byte index and 32-byte digest and
    // establishes NEON.
    unsafe {
        let zero = vdupq_n_u32(0);
        let head = row16(d);
        let head = vsetq_lane_u32::<0>(word4(i), vextq_u32::<3>(head, head));
        [
            head,
            row16(&d[12..]),
            vsetq_lane_u32::<0>(word4(&d[28..]), zero),
            zero,
        ]
    }
}

/// Load one of the exact supported layouts without crossing any part boundary.
///
/// # Safety
///
/// The caller must establish NEON availability.
#[inline(always)]
pub(super) unsafe fn load_parts(
    left: &[&[u8]],
    right: &[&[u8]],
) -> Option<(PairRows, Option<PairRows>, usize)> {
    Some(match (left, right) {
        ([lp, ld], [rp, rd])
            if lp.len() == 8 && ld.len() == 32 && rp.len() == 8 && rd.len() == 32 =>
        {
            // SAFETY: Both positions are eight bytes and both digests are 32 bytes.
            unsafe { ([leaf_rows(lp, ld), leaf_rows(rp, rd)], None, 40) }
        }
        ([ll, lr], [rl, rr])
            if ll.len() == 32 && lr.len() == 32 && rl.len() == 32 && rr.len() == 32 =>
        {
            // SAFETY: Each child digest is 32 bytes.
            unsafe { ([child_rows(ll, lr), child_rows(rl, rr)], None, 64) }
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
                let zero = vdupq_n_u32(0);
                (
                    [node_rows(lp, ll, lr), node_rows(rp, rl, rr)],
                    Some([
                        [row8(&lr[24..]), zero, zero, zero],
                        [row8(&rr[24..]), zero, zero, zero],
                    ]),
                    72,
                )
            }
        }
        ([li, ld], [ri, rd])
            if li.len() == 4 && ld.len() == 32 && ri.len() == 4 && rd.len() == 32 =>
        {
            // SAFETY: Each index contains four bytes and each digest contains 32 bytes.
            unsafe { ([indexed_rows(li, ld), indexed_rows(ri, rd)], None, 36) }
        }
        _ => return None,
    })
}

/// Hash two validated part layouts with duplicated SHA-3 words.
///
/// # Safety
///
/// The caller must establish NEON and SHA-3 availability.
#[target_feature(enable = "neon,sha3")]
unsafe fn hash_pair_parts_sha3(left: &[&[u8]], right: &[&[u8]]) -> Option<[[u8; OUT_LEN]; 2]> {
    // SAFETY: NEON is enabled for this function.
    let ([left_rows, right_rows], tail, len) = unsafe { load_parts(left, right)? };

    // SAFETY: The shape guard established all input extents. This function
    // enables SHA-3 and NEON, and each message is one BLAKE3 chunk.
    unsafe {
        let mut cv = iv::<Dup, 2>();
        let message = block(left_rows, right_rows);
        let flags = if tail.is_some() {
            CHUNK_START
        } else {
            CHUNK_START | CHUNK_END | ROOT
        };
        compress(&mut cv, &message, 0, len.min(BLOCK_LEN), flags);
        if let Some([left_tail, right_tail]) = tail {
            let message = block(left_tail, right_tail);
            compress(&mut cv, &message, 0, 8, CHUNK_END | ROOT);
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

    /// Check every direct layout, given as fields in separate allocations at
    /// every alignment, against the reference.
    #[test]
    fn test_exact_part_layouts_match_reference_with_unaligned_separate_allocations() {
        if !supported() || !(supports_sve2() || supports_sha3()) {
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
                if supports_sha3() {
                    // SAFETY: NEON and SHA-3 availability were established.
                    let duplicated = unsafe { hash_pair_parts_sha3(&left, &right) };
                    assert_eq!(duplicated, Some([left_digest, right_digest]));
                }
                assert_eq!(
                    hash_pair_parts(&left, &left),
                    Some([left_digest, left_digest]),
                    "aliased inputs"
                );
            }
        }
    }

    /// Check that inputs outside the direct layouts are rejected.
    #[test]
    fn test_unsupported_part_layouts_return_none() {
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
