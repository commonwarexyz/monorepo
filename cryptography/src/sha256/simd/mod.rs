use super::{Digest, DIGEST_LENGTH};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

pub(super) const BLOCK_LENGTH: usize = 64;
pub(super) const FINAL_BLOCKS: usize = 2;
pub(super) const STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

#[repr(align(16))]
pub(super) struct Align16<T>(pub T);

pub(super) static K: Align16<[u32; 64]> = Align16([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
    0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1,
    0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,
    0xbef9a3f7, 0xc67178f2,
]);

pub(super) fn hash_pair(left: &[u8], right: &[u8]) -> Option<(Digest, Digest)> {
    if left.len() != right.len() {
        return None;
    }

    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "aarch64", target_feature = "sha2"))] {
            Some(aarch64::hash_pair(left, right))
        } else if #[cfg(all(target_arch = "aarch64", feature = "std"))] {
            if std::arch::is_aarch64_feature_detected!("sha2") {
                return Some(aarch64::hash_pair(left, right));
            }
            None
        } else if #[cfg(all(
            target_arch = "x86_64",
            target_feature = "sha",
            target_feature = "avx2",
            target_feature = "ssse3",
            target_feature = "sse4.1",
        ))] {
            Some(x86_64::hash_pair(left, right))
        } else if #[cfg(all(target_arch = "x86_64", feature = "std"))] {
            if std::arch::is_x86_feature_detected!("sha")
                && std::arch::is_x86_feature_detected!("avx2")
                && std::arch::is_x86_feature_detected!("ssse3")
                && std::arch::is_x86_feature_detected!("sse4.1")
            {
                return Some(x86_64::hash_pair(left, right));
            }
            None
        } else {
            None
        }
    }
}

pub(super) fn final_blocks(message: &[u8]) -> ([[u8; BLOCK_LENGTH]; FINAL_BLOCKS], usize) {
    let mut blocks = [[0u8; BLOCK_LENGTH]; FINAL_BLOCKS];
    let tail = message.len() % BLOCK_LENGTH;
    let tail_start = message.len() - tail;
    blocks[0][..tail].copy_from_slice(&message[tail_start..]);
    blocks[0][tail] = 0x80;

    let block_count = if tail <= BLOCK_LENGTH - 9 { 1 } else { 2 };
    blocks[block_count - 1][BLOCK_LENGTH - 8..]
        .copy_from_slice(&((message.len() as u64) * 8).to_be_bytes());
    (blocks, block_count)
}

pub(super) fn digest(words: [u32; 8]) -> Digest {
    let mut digest = [0u8; DIGEST_LENGTH];
    for (i, word) in words.into_iter().enumerate() {
        digest[i * 4..][..4].copy_from_slice(&word.to_be_bytes());
    }
    Digest(digest)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn digests(output: [u8; DIGEST_LENGTH * 2]) -> (Digest, Digest) {
    // SAFETY: `Digest` is transparent over `[u8; 32]`, so `[u8; 64]` has the same layout as two digests.
    let [left, right]: [Digest; 2] = unsafe { core::mem::transmute(output) };
    (left, right)
}
