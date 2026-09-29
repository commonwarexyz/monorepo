use super::{input::Input, pair, row4, supports_avx2, supports_avx512, supports_avx512vl};
use crate::{Hasher as _, blake3::Blake3};
use core::{arch::x86_64::_mm_storeu_si128, cell::Cell};
use std::panic::{AssertUnwindSafe, catch_unwind};

// Each fragment ends at its allocation boundary; prefix bytes vary alignment.
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

#[test]
fn test_direct_input_extents() {
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

#[test]
fn test_direct_pair_backends() {
    if !supports_avx2() {
        return;
    }
    for len in [40, 64, 72] {
        for left_multipart in [false, true] {
            for right_multipart in [false, true] {
                for alignment in 0..32 {
                    let left_buffers = fragments(len, left_multipart, alignment, 9);
                    let right_buffers = fragments(len, right_multipart, 31 - alignment, 173);
                    let left_parts: Vec<_> = left_buffers.iter().map(|b| &b[alignment..]).collect();
                    let right_parts: Vec<_> =
                        right_buffers.iter().map(|b| &b[31 - alignment..]).collect();
                    let left = Input::new(&left_parts).unwrap();
                    let right = Input::new(&right_parts).unwrap();
                    let expected = [reference(&left_parts), reference(&right_parts)];
                    // SAFETY: AVX2 was checked and both inputs have length len.
                    assert_eq!(unsafe { pair::hash_direct(&left, &right) }, expected);
                    assert_eq!(super::hash_pair(&left_parts, &right_parts), Some(expected));
                    if supports_avx512vl() {
                        // SAFETY: AVX2, AVX-512F, and AVX-512VL were checked;
                        // both inputs have length len.
                        assert_eq!(unsafe { pair::hash_direct_vl(&left, &right) }, expected);
                    }
                    // The two messages may alias, as may digest fragments.
                    // SAFETY: AVX2 was checked above; Input validates extents.
                    assert_eq!(unsafe { pair::hash_direct(&left, &left) }, [expected[0]; 2]);
                }
            }
        }
    }
    let bytes = [0x55; 32];
    let repeated = [&bytes[..], &bytes[..]];
    assert_eq!(
        super::hash_pair(&repeated, &repeated),
        Some([reference(&repeated); 2])
    );
}

#[test]
fn test_row4_lanes_and_batch() {
    if !supports_avx512() {
        return;
    }
    for len in [40, 64, 72] {
        for alignment in 0..32 {
            let buffers: [_; 4] =
                core::array::from_fn(|lane| fragments(len, false, alignment, 17 + lane as u8 * 43));
            let inputs: [_; 4] = core::array::from_fn(|lane| &buffers[lane][0][alignment..]);
            for active in [3, 4] {
                let mut lanes = inputs;
                if active == 3 {
                    lanes[3] = lanes[0];
                }
                let expected: [_; 4] = core::array::from_fn(|lane| reference(&[lanes[lane]]));
                // SAFETY: AVX-512F was checked; all inputs have the same
                // supported length, with exact allocation extents.
                assert_eq!(unsafe { row4::hash(lanes) }, expected);
                let actual = super::hash_many(&lanes[..active]).unwrap();
                for (digest, expected) in actual.iter().zip(&expected[..active]) {
                    assert_eq!(digest.as_ref(), expected);
                }
                assert_eq!(actual.len(), active);
            }
        }
    }
}

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
        // The middle lane of the final batch changes length after grouping.
        // Kernels must reject unequal captured slices before compressing them.
        let result = catch_unwind(AssertUnwindSafe(|| Blake3::hash_many(&messages)));
        assert!(result.is_err(), "count={count}");
    }
}
