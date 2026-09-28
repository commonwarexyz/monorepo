use super::{Digest, Nodes, batch};
use crate::blake3::PAIR_LEN;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blake3::{BLOCK_LEN, OUT_LEN};

mod avx2;
mod avx512;
mod pair;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        /// Return whether AVX2 is available.
        #[inline]
        fn supports_avx2() -> bool {
            std::arch::is_x86_feature_detected!("avx2")
        }

        /// Return whether AVX-512F is available.
        #[inline]
        fn supports_avx512() -> bool {
            std::arch::is_x86_feature_detected!("avx512f")
        }

        /// Return whether AVX-512F and AVX-512VL are available.
        #[inline]
        fn supports_avx512vl() -> bool {
            std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512vl")
        }
    } else {
        /// Return whether AVX2 is statically enabled.
        const fn supports_avx2() -> bool {
            cfg!(target_feature = "avx2")
        }

        /// Return whether AVX-512F is statically enabled.
        const fn supports_avx512() -> bool {
            cfg!(target_feature = "avx512f")
        }

        /// Return whether AVX-512F and AVX-512VL are statically enabled.
        const fn supports_avx512vl() -> bool {
            cfg!(all(target_feature = "avx512f", target_feature = "avx512vl"))
        }
    }
}

/// Hash two `len`-byte zero-padded messages with the AVX2 pair kernel.
#[inline]
pub(super) fn hash_pair(
    left: &[u8; PAIR_LEN],
    right: &[u8; PAIR_LEN],
    len: usize,
) -> Option<[[u8; OUT_LEN]; 2]> {
    if !supports_avx2() {
        return None;
    }

    // Two-block pairs are bound by the latency of the chained compressions,
    // which single-instruction AVX-512VL rotates shorten. Consecutive
    // single-block pairs overlap instead, and run faster with AVX2 rotates
    // (measured on Zen 5).
    if len > BLOCK_LEN && supports_avx512vl() {
        // SAFETY: AVX2, AVX-512F, and AVX-512VL availability was established
        // above.
        return Some(unsafe { pair::hash_pair_vl(left, right, len) });
    }

    // SAFETY: AVX2 availability was established above.
    Some(unsafe { pair::hash_pair(left, right, len) })
}

/// AVX-512 kernels. A value exists only once AVX-512F is available.
struct Avx512(());

impl Avx512 {
    /// Hash equal-length `messages` with their nodes packed into lanes (see
    /// [`super::pack`]), compiled once here rather than in each caller.
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
        // SAFETY: AVX-512F availability was established on construction.
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
    /// [`super::pack`]), compiled once here rather than in each caller.
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
    if supports_avx512() {
        let pack = |messages: &[&[u8]], digests: &mut _| Avx512(()).pack(messages, digests);
        return Some(batch(messages, avx512::MINIMUM, pack, |inputs, _| {
            // SAFETY: AVX-512F availability was established above.
            unsafe { avx512::hash_x16(inputs) }
        }));
    }
    if supports_avx2() {
        let pack = |messages: &[&[u8]], digests: &mut _| Avx2(()).pack(messages, digests);
        return Some(batch(messages, avx2::MINIMUM, pack, |inputs, _| {
            // SAFETY: AVX2 availability was established above.
            unsafe { avx2::hash_x8(inputs) }
        }));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake3::{
        gather,
        simd::tests::{check_batch, check_lanes},
    };

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

        // SAFETY: AVX-512F availability was checked above.
        check_lanes::<16>(|inputs| unsafe { avx512::hash_x16(inputs) });
    }

    #[test]
    fn test_avx2_batch_matches_reference() {
        if !supports_avx2() {
            return;
        }
        let pack = |messages: &[&[u8]], digests: &mut _| Avx2(()).pack(messages, digests);
        check_batch(|messages| {
            batch(messages, avx2::MINIMUM, pack, |inputs, _| {
                // SAFETY: AVX2 availability was checked above.
                unsafe { avx2::hash_x8(inputs) }
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
            batch(messages, avx512::MINIMUM, pack, |inputs, _| {
                // SAFETY: AVX-512F availability was checked above.
                unsafe { avx512::hash_x16(inputs) }
            })
        });
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
