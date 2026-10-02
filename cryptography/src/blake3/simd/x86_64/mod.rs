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
mod pair36;
mod row;
mod row4;

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
    if let Some(left) = pair36::Input::new(left)
        && let Some(right) = pair36::Input::new(right)
        && supports_avx512vl()
    {
        // SAFETY: AVX2, AVX-512F, and AVX-512VL were established above,
        // and both inputs validate exactly 36 bytes.
        return Some(unsafe { pair36::hash(&left, &right) });
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
    /// Hash equal-length messages, using the row kernel for three or four
    /// short inputs.
    #[inline]
    fn hash(&self, inputs: [&[u8]; 16], active: usize) -> [[u8; OUT_LEN]; 16] {
        if matches!(active, 3 | 4) && input::Input::supports_len(inputs[0].len()) {
            // SAFETY: Construction establishes AVX-512F and the first input
            // has a supported length. The kernel checks that all lanes agree.
            let rows = unsafe { row4::hash([inputs[0], inputs[1], inputs[2], inputs[3]]) };
            let mut outputs = [[0; OUT_LEN]; 16];
            outputs[..active].copy_from_slice(&rows[..active]);
            return outputs;
        }
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
    if matches!(messages.len(), 3 | 4)
        && let Some(digests) = hash_rows(messages)
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

/// Keep the row inputs and outputs in a separate frame from the general
/// batch dispatcher.
#[inline(never)]
fn hash_rows<M: AsRef<[u8]>>(messages: &[M]) -> Option<Vec<Digest>> {
    if !supports_avx512() {
        return None;
    }
    let [first, second, third, rest @ ..] = messages else {
        return None;
    };
    if rest.len() > 1 {
        return None;
    }
    let first = first.as_ref();
    let inputs = [
        first,
        second.as_ref(),
        third.as_ref(),
        rest.first().map_or(first, AsRef::as_ref),
    ];
    let len = inputs[0].len();
    if inputs.iter().any(|input| input.len() != len) {
        return None;
    }
    if len == 36 {
        let parts = inputs.each_ref().map(core::slice::from_ref);
        return hash_leaves36(parts, messages.len());
    }
    if !input::Input::supports_len(len) {
        return None;
    }

    // SAFETY: AVX-512F is available, and all captured slices have the same
    // supported length.
    let outputs = unsafe { row4::hash(inputs) };
    Some(
        outputs
            .into_iter()
            .take(messages.len())
            .map(Digest)
            .collect(),
    )
}

/// Hash three or four messages directly from supported fragments.
pub(super) fn hash_many_parts<const P: usize>(messages: &[[&[u8]; P]]) -> Option<Vec<Digest>> {
    if !matches!(messages.len(), 3 | 4) || !supports_avx512() {
        return None;
    }
    let last = messages.get(3).unwrap_or(&messages[2]);
    if let Some(digests) = hash_leaves36(
        [&messages[0], &messages[1], &messages[2], last],
        messages.len(),
    ) {
        return Some(digests);
    }
    let inputs = [
        input::Input::new(&messages[0])?,
        input::Input::new(&messages[1])?,
        input::Input::new(&messages[2])?,
        input::Input::new(messages.get(3).unwrap_or(&messages[0]))?,
    ];
    if inputs.iter().any(|input| input.len() != inputs[0].len()) {
        return None;
    }

    // SAFETY: AVX-512F is available, each Input validates its fragments,
    // and every captured message has the same supported length.
    let outputs = unsafe { row4::hash_parts(inputs.each_ref()) };
    Some(
        outputs
            .into_iter()
            .take(messages.len())
            .map(Digest)
            .collect(),
    )
}

/// Hash the first `count` (three or four) of four 36-byte messages, such as
/// BMT leaves, two at a time with the 36-byte pair kernel.
///
/// The row kernel has no 36-byte shape. Returns `None` when AVX-512VL is
/// unavailable or a message is neither one 36-byte part nor a 4-byte part
/// followed by a 32-byte part.
fn hash_leaves36(messages: [&[&[u8]]; 4], count: usize) -> Option<Vec<Digest>> {
    if !supports_avx2() || !supports_avx512vl() {
        return None;
    }
    let [first, second, third, fourth] = messages;
    let (first, second) = (pair36::Input::new(first)?, pair36::Input::new(second)?);
    let (third, fourth) = (pair36::Input::new(third)?, pair36::Input::new(fourth)?);

    // SAFETY: AVX2, AVX-512F, and AVX-512VL were established above, and each
    // input validates exactly 36 bytes.
    let digests = unsafe { [pair36::hash(&first, &second), pair36::hash(&third, &fourth)] };
    Some(
        digests
            .into_iter()
            .flatten()
            .take(count)
            .map(Digest)
            .collect(),
    )
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
    use crate::{
        Hasher as _,
        blake3::{
            Blake3, gather,
            simd::tests::{check_batch, check_lanes},
        },
    };
    use blake3::CHUNK_LEN;
    use commonware_utils::{iter::zip_eq, test_rng};
    use core::{arch::x86_64::_mm_storeu_si128, cell::Cell};
    use rand::Rng as _;
    use std::panic::{AssertUnwindSafe, catch_unwind};

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

    /// Check the row kernel and the three- and four-message batch dispatch against
    /// the reference with exactly sized contiguous messages.
    #[test]
    fn test_row4_lanes_and_batch() {
        if !supports_avx512() {
            return;
        }
        for len in [40, 64, 72] {
            for alignment in 0..32 {
                let buffers: [_; 4] = core::array::from_fn(|lane| {
                    fragments(len, false, alignment, 17 + lane as u8 * 43)
                });
                let inputs: [_; 4] = core::array::from_fn(|lane| &buffers[lane][0][alignment..]);
                for active in [3, 4] {
                    // Three active lanes repeat the first message in the fourth.
                    let mut lanes = inputs;
                    if active == 3 {
                        lanes[3] = lanes[0];
                    }
                    let expected: [_; 4] = core::array::from_fn(|lane| reference(&[lanes[lane]]));

                    // SAFETY: AVX-512F was checked. All inputs have the same
                    // supported length, with exact allocation extents.
                    assert_eq!(unsafe { row4::hash(lanes) }, expected);

                    // The batch dispatch hashes the active messages.
                    let actual = super::hash_many(&lanes[..active]).unwrap();
                    for (digest, expected) in actual.iter().zip(&expected[..active]) {
                        assert_eq!(digest.as_ref(), expected);
                    }
                    assert_eq!(actual.len(), active);
                }
            }
        }
    }

    /// Check three or four messages of `sizes` fragments, each in its own
    /// allocation at varying alignments, against the reference, including aliased
    /// messages.
    fn check_multipart_row4<const P: usize>(sizes: [usize; P]) {
        for alignment in 0..32 {
            let buffers: [[(Box<[u8]>, usize); P]; 4] = core::array::from_fn(|lane| {
                core::array::from_fn(|part| {
                    let offset = (alignment + lane * 7 + part * 11) % 32;
                    let salt = (17 + lane * 43 + part * 31) as u8;
                    let buffer = fragments(sizes[part], false, offset, salt).pop().unwrap();
                    (buffer, offset)
                })
            });
            let messages: [[&[u8]; P]; 4] = core::array::from_fn(|lane| {
                core::array::from_fn(|part| {
                    let (buffer, offset) = &buffers[lane][part];
                    &buffer[*offset..]
                })
            });
            let expected: [_; 4] = core::array::from_fn(|lane| reference(&messages[lane]));
            for active in [3, 4] {
                let actual = super::hash_many_parts(&messages[..active]).unwrap();
                assert_eq!(actual.len(), active);
                for (digest, expected) in zip_eq(&actual, &expected[..active]) {
                    assert_eq!(digest.as_ref(), expected);
                }
                let public = Blake3::hash_many_parts(&messages[..active]);
                for (digest, expected) in zip_eq(&public, &expected[..active]) {
                    assert_eq!(digest.as_ref(), expected);
                }
                assert_eq!(public.len(), active);
            }

            // Messages may alias one another.
            let mut aliases = messages;
            aliases[1] = aliases[0];
            aliases[3] = aliases[2];
            for active in [3, 4] {
                let actual = super::hash_many_parts(&aliases[..active]).unwrap();
                for (digest, parts) in zip_eq(&actual, &aliases[..active]) {
                    assert_eq!(digest.as_ref(), reference(parts));
                }
            }
        }
    }

    /// Check the row kernel on the merkle layouts with exactly sized fragments,
    /// including digest fragments that share one allocation.
    #[test]
    fn test_row4_multipart_fragment_extents_and_aliases() {
        if !supports_avx512() {
            return;
        }

        // Each fragment has its own allocation.
        check_multipart_row4([8, 32]);
        check_multipart_row4([32, 32]);
        check_multipart_row4([8, 32, 32]);

        // Both digest fragments share one exact-size allocation.
        let position = fragments(8, false, 7, 11).pop().unwrap();
        let digest = fragments(32, false, 13, 97).pop().unwrap();
        let aliased = [&position[7..], &digest[13..], &digest[13..]];
        let messages = [aliased; 4];
        for active in [3, 4] {
            let actual = super::hash_many_parts(&messages[..active]).unwrap();
            for output in actual {
                assert_eq!(output.as_ref(), reference(&aliased));
            }
        }
    }

    /// Check that three or four messages of `layouts`, with one message of a
    /// different layout, bypass the row kernel and still hash correctly.
    fn check_mixed_rows<const P: usize>(layouts: &[[&[u8]; P]]) {
        for (i, &common) in layouts.iter().enumerate() {
            for (j, &odd) in layouts.iter().enumerate() {
                if i == j {
                    continue;
                }
                for count in [3, 4] {
                    for position in 0..count {
                        let mut messages = vec![common; count];
                        messages[position] = odd;
                        assert!(super::hash_many_parts(&messages).is_none());
                        let actual = Blake3::hash_many_parts(&messages);
                        for (digest, parts) in zip_eq(&actual, &messages) {
                            assert_eq!(digest.as_ref(), reference(parts));
                        }
                    }
                }
            }
        }
    }

    /// Check that three or four messages with layouts of different lengths bypass
    /// the row kernel and still hash correctly.
    #[test]
    fn test_row4_parts_rejects_mixed_lengths() {
        if !supports_avx512() {
            return;
        }
        let data: Vec<u8> = (0..72u8).map(|i| i.wrapping_mul(37)).collect();

        // The two-part layouts.
        check_mixed_rows(&[[&data[..8], &data[8..40]], [&data[..32], &data[32..64]]]);

        // One-part messages of every supported length.
        check_mixed_rows(&[[&data[..40]], [&data[..64]], [&data[..72]]]);
    }

    /// Check batches with a message whose view shortens after two conversions.
    #[test]
    fn test_row4_rejects_changed_input_lengths() {
        if !supports_avx512() {
            return;
        }
        struct Message {
            bytes: [u8; 64],
            calls: Cell<usize>,
            shorten: bool,
        }
        impl AsRef<[u8]> for Message {
            fn as_ref(&self) -> &[u8] {
                let calls = self.calls.replace(self.calls.get() + 1);
                if self.shorten && calls >= 2 {
                    &self.bytes[..1]
                } else {
                    &self.bytes
                }
            }
        }
        for count in [3, 4, 19, 20] {
            let messages: Vec<_> = (0..count)
                .map(|index| Message {
                    bytes: [0x5a; 64],
                    calls: Cell::new(0),
                    shorten: index == count / 16 * 16 + 1,
                })
                .collect();

            // A direct batch may capture the initial views before any changes.
            // Grouped batches must reject unequal captured slices.
            let result = catch_unwind(AssertUnwindSafe(|| Blake3::hash_many(&messages)));
            if let Ok(digests) = result {
                assert!(count < 16, "count={count}");
                assert_eq!(digests.len(), count);
                for digest in digests {
                    assert_eq!(digest.as_ref(), &reference(&[&[0x5a; 64]]));
                }
            }
        }
    }

    /// Check that the row dispatch hashes the views it captures, declines
    /// unsupported or unequal lengths, and sends 36-byte messages to the 36-byte
    /// pair kernel.
    #[test]
    fn test_row_dispatch_captured_views() {
        if !supports_avx512() {
            return;
        }
        struct Message<'a> {
            initial: &'a [u8],
            later: &'a [u8],
            captured: Cell<bool>,
        }
        impl AsRef<[u8]> for Message<'_> {
            fn as_ref(&self) -> &[u8] {
                if self.captured.replace(true) {
                    self.later
                } else {
                    self.initial
                }
            }
        }
        let buffers = fragments(72, false, 7, 31);
        let full = &buffers[0][7..];
        for active in [3, 4] {
            // Views after the first are one byte long.
            let messages: Vec<_> = (0..active)
                .map(|_| Message {
                    initial: full,
                    later: &full[..1],
                    captured: Cell::new(false),
                })
                .collect();
            let actual = super::hash_rows(&messages).unwrap();
            assert_eq!(actual.len(), active);
            for digest in actual {
                assert_eq!(digest.as_ref(), &reference(&[full]));
            }

            // One message of another length declines the row kernel.
            for unsupported in [1, 36, 40, 64] {
                let mut inputs = vec![full; active];
                inputs[1] = &full[..unsupported];
                assert!(super::hash_rows(&inputs).is_none());
            }

            // 36-byte messages go two at a time to the 36-byte pair kernel.
            let leaves = vec![&full[..36]; active];
            let actual = super::hash_rows(&leaves);
            assert_eq!(actual.is_some(), supports_avx512vl());
            for digest in actual.into_iter().flatten() {
                assert_eq!(digest.as_ref(), &reference(&[&full[..36]]));
            }

            // The batch dispatch reaches the row kernel.
            let actual = super::hash_many(&vec![full; active]).unwrap();
            for digest in actual {
                assert_eq!(digest.as_ref(), &reference(&[full]));
            }
        }
    }

    /// Check that three or four messages of a 4-byte part and a 32-byte part hash
    /// directly with the 36-byte pair kernel exactly when AVX-512 and AVX-512VL
    /// are available.
    #[test]
    fn test_leaves36_parts() {
        let positions = random(4, 4);
        let digests = random(4, 32);
        let messages: [[&[u8]; 2]; 4] =
            core::array::from_fn(|lane| [&positions[lane][..], &digests[lane][..]]);
        for count in [3, 4] {
            let actual = super::hash_many_parts(&messages[..count]);
            assert_eq!(actual.is_some(), supports_avx512() && supports_avx512vl());
            if let Some(actual) = actual {
                for (digest, parts) in zip_eq(&actual, &messages[..count]) {
                    assert_eq!(digest.as_ref(), reference(parts));
                }
            }
        }
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
