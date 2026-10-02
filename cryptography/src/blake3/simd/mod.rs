//! BLAKE3 kernels for merkle node pairs.

use super::{Digest, gather};

#[cfg(target_arch = "x86_64")]
mod x86_64;

/// The BLAKE3 initial chaining value (the SHA-256 initial hash values).
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Domain flag for the first block of a chunk.
const CHUNK_START: u32 = 1 << 0;

/// Domain flag for the last block of a chunk.
const CHUNK_END: u32 = 1 << 1;

/// Domain flag for the root node.
const ROOT: u32 = 1 << 3;

/// Hash two messages, each given as parts, with the pair kernel for the
/// current CPU.
///
/// Returns `None` when no kernel is available, the messages differ in length,
/// or either exceeds [`PAIR_LEN`](super::PAIR_LEN) bytes.
#[inline]
pub(super) fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> Option<(Digest, Digest)> {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            let [left, right] = x86_64::hash_pair(left, right)?;
            Some((Digest(left), Digest(right)))
        } else if #[cfg(any(target_feature = "neon", feature = "std"))] {
        } else {
            let _ = (left, right);
            None
        }
    }
}
