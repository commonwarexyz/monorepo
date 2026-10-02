//! BLAKE3 kernels for x86_64 with AVX2 and AVX-512.

use super::{Digest, Nodes, batch};
use crate::blake3::PAIR_LEN;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blake3::{BLOCK_LEN, OUT_LEN};

mod avx2;
mod avx512;
mod input;
mod pair;
mod row;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        /// Return whether AVX2 is available.
        #[inline]
        pub(super) fn supports_avx2() -> bool {
            std::arch::is_x86_feature_detected!("avx2")
        }

        /// Return whether AVX-512F and AVX-512BW are available.
        #[inline]
        fn supports_avx512() -> bool {
            std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512bw")
        }

        /// Return whether AVX-512F and AVX-512VL are available.
        #[inline]
        fn supports_avx512vl() -> bool {
            std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512vl")
        }
    } else {
        /// Return whether AVX2 is statically enabled.
        pub(super) const fn supports_avx2() -> bool {
            cfg!(target_feature = "avx2")
        }

        /// Return whether AVX-512F and AVX-512BW are statically enabled.
        const fn supports_avx512() -> bool {
            cfg!(all(target_feature = "avx512f", target_feature = "avx512bw"))
        }

        /// Return whether AVX-512F and AVX-512VL are statically enabled.
        const fn supports_avx512vl() -> bool {
            cfg!(all(target_feature = "avx512f", target_feature = "avx512vl"))
        }
    }
}

/// Hash two messages, each given as parts, with the AVX2 pair kernel.
///
/// Returns `None` when AVX2 is unavailable, the messages differ in length, or
/// either exceeds [`PAIR_LEN`] bytes.
#[inline]
pub(super) fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> Option<[[u8; OUT_LEN]; 2]> {
    if !supports_avx2() {
        return None;
    }
    if let Some(left) = input::Input::new(left)
        && let Some(right) = input::Input::new(right)
    {
        if left.len() != right.len() {
            return None;
        }
        if supports_avx512vl() {
            // SAFETY: AVX2, AVX-512F, AVX-512VL, and equal input lengths were
            // established above.
            return Some(unsafe { pair::hash_direct_vl(&left, &right) });
        }

        // SAFETY: AVX2 and equal input lengths were established above.
        return Some(unsafe { pair::hash_direct(&left, &right) });
    }
    let (mut left_buffer, mut right_buffer) = ([0u8; PAIR_LEN], [0u8; PAIR_LEN]);
    let len = gather(left, &mut left_buffer)?;
    if gather(right, &mut right_buffer)? != len {
        return None;
    }
    let (left, right) = (&left_buffer, &right_buffer);

    // Two-block pairs are bound by the latency of the chained compressions,
    // which single-instruction AVX-512VL rotates shorten. Consecutive
    // single-block pairs overlap instead, and run faster with AVX2 rotates.
    if len > BLOCK_LEN && supports_avx512vl() {
        // SAFETY: AVX2, AVX-512F, and AVX-512VL availability was established
        // above.
        return Some(unsafe { pair::hash_pair_vl(left, right, len) });
    }

    // SAFETY: AVX2 availability was established above.
    Some(unsafe { pair::hash_pair(left, right, len) })
}

/// Copy the concatenation of `parts` into `buffer`, zero-padded, returning its
/// length, or `None` if it exceeds [`PAIR_LEN`] bytes.
///
/// A load that spans several stores cannot forward from them and waits until
/// they reach the cache. Copying part by part leaves such loads wherever a
/// part ends inside one of the kernel's 16-byte loads, so parts of whole
/// 32-bit words are assembled in registers and each half block is written with
/// one store.
#[inline]
fn gather(parts: &[&[u8]], buffer: &mut [u8; PAIR_LEN]) -> Option<usize> {
    if supports_avx2() {
        // SAFETY: AVX2 availability was established above.
        if let Some(len) = unsafe { pair::gather(parts, buffer) } {
            return Some(len);
        }
    }
    let (gathered, len) = super::gather(parts)?;
    *buffer = gathered;
    Some(len)
}

/// AVX-512 kernels. A value exists only once AVX-512F and AVX-512BW are
/// available.
struct Avx512(());

impl Avx512 {
    /// Hash equal-length messages.
    #[inline]
    fn hash(&self, inputs: [&[u8]; 16], active: usize) -> [[u8; OUT_LEN]; 16] {
        pair_batch(inputs, active).unwrap_or_else(|| {
            // SAFETY: Construction establishes AVX-512F and AVX-512BW.
            unsafe { avx512::hash_x16(inputs) }
        })
    }

    /// Hash equal-length `messages` with their nodes packed into lanes (see
    /// [`super::pack`]).
    fn pack(&self, messages: &[&[u8]], digests: &mut Vec<Digest>) {
        super::pack(self, messages, digests);
    }
}

impl Nodes<16> for Avx512 {
    fn leaves(&self, inputs: [&[u8]; 16], counters: [u64; 16], _: usize) -> [[u8; OUT_LEN]; 16] {
        // SAFETY: AVX-512F availability was established on construction.
        unsafe { avx512::leaves_x16(inputs, counters) }
    }

    fn tails(&self, inputs: [&[u8]; 16], _: usize) -> [[u8; OUT_LEN]; 16] {
        // SAFETY: AVX-512F and AVX-512BW availability was established on
        // construction.
        unsafe { avx512::tails_x16(inputs) }
    }

    fn parents(
        &self,
        children: [&[u8; BLOCK_LEN]; 16],
        root: u32,
        _: usize,
    ) -> [[u8; OUT_LEN]; 16] {
        // SAFETY: AVX-512F availability was established on construction.
        unsafe { avx512::parents_x16(children, root) }
    }
}

/// AVX2 kernels. A value exists only once AVX2 is available.
struct Avx2(());

impl Avx2 {
    /// Hash equal-length `messages` with their nodes packed into lanes (see
    /// [`super::pack`]).
    fn pack(&self, messages: &[&[u8]], digests: &mut Vec<Digest>) {
        super::pack(self, messages, digests);
    }
}

impl Nodes<8> for Avx2 {
    fn leaves(&self, inputs: [&[u8]; 8], counters: [u64; 8], _: usize) -> [[u8; OUT_LEN]; 8] {
        // SAFETY: AVX2 availability was established on construction.
        unsafe { avx2::leaves_x8(inputs, counters) }
    }

    fn tails(&self, inputs: [&[u8]; 8], _: usize) -> [[u8; OUT_LEN]; 8] {
        // SAFETY: AVX2 availability was established on construction.
        unsafe { avx2::tails_x8(inputs) }
    }

    fn parents(&self, children: [&[u8; BLOCK_LEN]; 8], root: u32, _: usize) -> [[u8; OUT_LEN]; 8] {
        // SAFETY: AVX2 availability was established on construction.
        unsafe { avx2::parents_x8(children, root) }
    }
}

/// Hash independent messages in batches of 16 (AVX-512) or 8 (AVX2).
pub(super) fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Option<Vec<Digest>> {
    if let [left, right] = messages
        && supports_avx2()
        && let Some(digests) = hash_two(left.as_ref(), right.as_ref())
    {
        return Some(digests);
    }
    if supports_avx512() {
        let pack = |messages: &[&[u8]], digests: &mut _| Avx512(()).pack(messages, digests);
        return Some(batch(messages, pack, |inputs, active| {
            Avx512(()).hash(inputs, active)
        }));
    }
    if supports_avx2() {
        let pack = |messages: &[&[u8]], digests: &mut _| Avx2(()).pack(messages, digests);
        return Some(batch(messages, pack, |inputs, active| {
            pair_batch(inputs, active).unwrap_or_else(|| {
                // SAFETY: AVX2 availability was established above.
                unsafe { avx2::hash_x8(inputs) }
            })
        }));
    }
    None
}

/// Keep the pair kernel's temporaries in a separate stack frame from the
/// general batch dispatcher.
#[inline(never)]
fn hash_two(left: &[u8], right: &[u8]) -> Option<Vec<Digest>> {
    let [left, right] = hash_pair(&[left], &[right])?;
    Some(Vec::from([Digest(left), Digest(right)]))
}

/// Hash a batch whose only active lanes are the first two with the two-message
/// kernel, when both messages fit it.
///
/// A pass of the batch kernel costs as much with idle lanes as with full ones,
/// while the two-message kernel holds each message's state in one vector and
/// does a fraction of that work. Spare outputs are zero.
fn pair_batch<const L: usize>(inputs: [&[u8]; L], active: usize) -> Option<[[u8; OUT_LEN]; L]> {
    if active != 2 {
        return None;
    }
    let pair = hash_pair(&[inputs[0]], &[inputs[1]])?;
    let mut outputs = [[0u8; OUT_LEN]; L];
    outputs[..2].copy_from_slice(&pair);
    Some(outputs)
}

#[cfg(test)]
mod tests {
    use super::{input::Input, *};
    use crate::blake3::{
        gather,
        simd::tests::{check_batch, check_lanes},
    };
    use blake3::CHUNK_LEN;
    use commonware_utils::{iter::zip_eq, test_rng};
    use core::arch::x86_64::_mm_storeu_si128;
    use rand::Rng as _;

    // Each fragment ends at its allocation boundary. Prefix bytes vary alignment.
    fn fragments(len: usize, multipart: bool, offset: usize, salt: u8) -> Vec<Box<[u8]>> {
        let sizes: &[usize] = match (len, multipart) {
            (40, true) => &[8, 32],
            (64, true) => &[32, 32],
            (72, true) => &[8, 32, 32],
            _ => core::slice::from_ref(&len),
        };
        let mut position = 0;
        sizes
            .iter()
            .map(|&size| {
                let mut bytes = vec![0xAA; offset + size].into_boxed_slice();
                for byte in &mut bytes[offset..] {
                    *byte = (position as u8).wrapping_mul(37).wrapping_add(salt);
                    position += 1;
                }
                bytes
            })
            .collect()
    }

    fn reference(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }

    /// Return `count` exactly sized messages of `len` random bytes.
    fn random(count: usize, len: usize) -> Vec<Box<[u8]>> {
        let mut rng = test_rng();
        (0..count)
            .map(|_| {
                let mut bytes = vec![0; len].into_boxed_slice();
                rng.fill_bytes(&mut bytes);
                bytes
            })
            .collect()
    }

    /// Check that direct loads read exactly each supported layout at every
    /// alignment, and that only the supported layouts are recognized.
    #[test]
    fn test_direct_input_extents() {
        // Each layout loads its zero-padded concatenation and rejects a shortened
        // fragment.
        for len in [40, 64, 72] {
            for multipart in [false, true] {
                for alignment in 0..32 {
                    let buffers = fragments(len, multipart, alignment, 7);
                    let parts: Vec<_> = buffers.iter().map(|b| &b[alignment..]).collect();
                    let input = Input::new(&parts).unwrap();
                    assert_eq!(input.len(), len);
                    let mut expected = [0; 128];
                    expected[..len].copy_from_slice(&parts.concat());
                    for offset in (0..128).step_by(16) {
                        let mut actual = [0; 16];

                        // SAFETY: SSE2 is available on x86_64, offsets are multiples
                        // of 16, and the destination holds the whole 16-byte store.
                        unsafe {
                            _mm_storeu_si128(actual.as_mut_ptr().cast(), input.load(offset));
                        }
                        assert_eq!(actual, expected[offset..offset + 16]);
                    }
                    for changed in 0..parts.len() {
                        let mut shorter = parts.clone();
                        shorter[changed] = &shorter[changed][..shorter[changed].len() - 1];
                        assert!(Input::new(&shorter).is_none());
                    }
                }
            }
        }

        // Contiguous messages of other lengths and other layouts are rejected.
        assert!(Input::new(&[]).is_none());
        assert!(Input::new(&[&[]]).is_none());
        let data = [0; 73];
        for len in 0..=73 {
            assert_eq!(
                Input::new(&[&data[..len]]).is_some(),
                matches!(len, 40 | 64 | 72)
            );
        }
        assert!(Input::new(&[&data[..32], &[], &data[..32]]).is_none());
        assert!(Input::new(&[&data[..8], &data[..16], &data[..16]]).is_none());
    }

    /// Check the direct pair kernels and the pair dispatch against the reference
    /// for every pair of layouts at complementary alignments.
    #[test]
    fn test_direct_pair_backends() {
        if !supports_avx2() {
            return;
        }

        // Each pair of layouts hashes from exactly sized fragments at
        // complementary alignments.
        for len in [40, 64, 72] {
            for left_multipart in [false, true] {
                for right_multipart in [false, true] {
                    for alignment in 0..32 {
                        let left_buffers = fragments(len, left_multipart, alignment, 9);
                        let right_buffers = fragments(len, right_multipart, 31 - alignment, 173);
                        let left_parts: Vec<_> =
                            left_buffers.iter().map(|b| &b[alignment..]).collect();
                        let right_parts: Vec<_> =
                            right_buffers.iter().map(|b| &b[31 - alignment..]).collect();
                        let left = Input::new(&left_parts).unwrap();
                        let right = Input::new(&right_parts).unwrap();
                        let expected = [reference(&left_parts), reference(&right_parts)];

                        // SAFETY: AVX2 was checked and both inputs have length len.
                        assert_eq!(unsafe { pair::hash_direct(&left, &right) }, expected);
                        assert_eq!(super::hash_pair(&left_parts, &right_parts), Some(expected));
                        if supports_avx512vl() {
                            // SAFETY: AVX2, AVX-512F, and AVX-512VL were checked.
                            // Both inputs have length len.
                            assert_eq!(unsafe { pair::hash_direct_vl(&left, &right) }, expected);
                        }

                        // The two messages may alias.
                        // SAFETY: AVX2 was checked above. Input validates extents.
                        assert_eq!(unsafe { pair::hash_direct(&left, &left) }, [expected[0]; 2]);
                    }
                }
            }
        }

        // Digest fragments may alias.
        let bytes = [0x55; 32];
        let repeated = [&bytes[..], &bytes[..]];
        assert_eq!(
            super::hash_pair(&repeated, &repeated),
            Some([reference(&repeated); 2])
        );
    }

    /// Check sixteen exactly sized messages that end in a partial block against
    /// the reference.
    #[test]
    fn test_partial_blocks_match_reference() {
        if !supports_avx2() {
            return;
        }
        for len in [1, 63, 65, 129] {
            let messages = random(16, len);
            let actual = super::hash_many(&messages).unwrap();
            for (digest, message) in zip_eq(&actual, &messages) {
                assert_eq!(digest.as_ref(), reference(&[message]));
            }
        }
    }

    /// Check two exactly sized messages of three chunks and one byte, whose full
    /// chunks, final partial chunks, and parents pack into lanes, against the
    /// reference.
    #[test]
    fn test_packed_trees_match_reference() {
        if !supports_avx2() {
            return;
        }
        let messages = random(2, 3 * CHUNK_LEN + 1);
        let actual = super::hash_many(&messages).unwrap();
        for (digest, message) in zip_eq(&actual, &messages) {
            assert_eq!(digest.as_ref(), reference(&[message]));
        }
    }

    #[test]
    fn test_avx2_lanes_match_reference() {
        if !supports_avx2() {
            return;
        }

        // SAFETY: AVX2 availability was checked above.
        check_lanes::<8>(|inputs| unsafe { avx2::hash_x8(inputs) });
    }

    #[test]
    fn test_avx512_lanes_match_reference() {
        if !supports_avx512() {
            return;
        }

        // SAFETY: AVX-512F and AVX-512BW availability was checked above.
        check_lanes::<16>(|inputs| unsafe { avx512::hash_x16(inputs) });
    }

    #[test]
    fn test_avx2_batch_matches_reference() {
        if !supports_avx2() {
            return;
        }
        let pack = |messages: &[&[u8]], digests: &mut _| Avx2(()).pack(messages, digests);
        check_batch(|messages| {
            batch(messages, pack, |inputs, active| {
                pair_batch(inputs, active).unwrap_or_else(|| {
                    // SAFETY: AVX2 availability was checked above.
                    unsafe { avx2::hash_x8(inputs) }
                })
            })
        });
    }

    #[test]
    fn test_avx512_batch_matches_reference() {
        if !supports_avx512() {
            return;
        }
        let pack = |messages: &[&[u8]], digests: &mut _| Avx512(()).pack(messages, digests);
        check_batch(|messages| {
            batch(messages, pack, |inputs, active| {
                Avx512(()).hash(inputs, active)
            })
        });
    }

    #[test]
    fn test_masked_gather_matches_gather() {
        if !supports_avx2() {
            return;
        }
        let data: Vec<u8> = (1..=PAIR_LEN as u8 + 1).collect();
        for len in 0..=PAIR_LEN + 1 {
            let message = &data[..len];
            for split in 0..=len {
                // Each part is its own allocation, so a read past any part is
                // out of bounds under Miri.
                let owned: [Box<[u8]>; 3] = [
                    message[..split].into(),
                    Box::default(),
                    message[split..].into(),
                ];
                let parts = owned.each_ref().map(|part| &part[..]);
                let words = parts.iter().all(|part| part.len() % 4 == 0);

                // The masked gather must write every byte of the buffer.
                let mut buffer = [0xAA; PAIR_LEN];

                // SAFETY: AVX2 availability was checked above.
                let masked = unsafe { pair::gather(&parts, &mut buffer) };
                match gather(&parts) {
                    Some((expected, expected_len)) if words => {
                        assert_eq!(masked, Some(expected_len), "len {len} split {split}");
                        assert_eq!(buffer, expected, "len {len} split {split}");
                    }
                    _ => assert_eq!(masked, None, "len {len} split {split}"),
                }
            }
        }
    }

    #[test]
    fn test_pair_matches_reference() {
        for len in 0..=PAIR_LEN {
            let left: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let right: Vec<u8> = (0..len).map(|i| !(i as u8)).collect();
            let (left_buffer, _) = gather(&[&left]).unwrap();
            let (right_buffer, _) = gather(&[&right]).unwrap();
            let expected = [
                *blake3::hash(&left).as_bytes(),
                *blake3::hash(&right).as_bytes(),
            ];
            if supports_avx2() {
                // SAFETY: AVX2 availability was checked above.
                let outputs = unsafe { pair::hash_pair(&left_buffer, &right_buffer, len) };
                assert_eq!(outputs, expected, "len {len}");
            }
            if supports_avx2() && supports_avx512vl() {
                // SAFETY: AVX2, AVX-512F, and AVX-512VL availability was
                // checked above.
                let outputs = unsafe { pair::hash_pair_vl(&left_buffer, &right_buffer, len) };
                assert_eq!(outputs, expected, "len {len}");
            }
        }
    }
}
