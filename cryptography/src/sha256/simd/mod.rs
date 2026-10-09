//! SHA-256 kernels for merkle node pairs and independent message batches.
//!
//! Modern SHA extensions (aarch64 SHA2, x86_64 SHA-NI) execute several
//! rounds per instruction but with multi-cycle latency, so a single message
//! leaves the SHA unit idle between dependent instructions. Interleaving two
//! independent messages fills those latency slots, making progress on both
//! digests at close to the unit's throughput limit.
//!
//! The kernels specialize the two merkle node shapes used across the
//! Merkle-family primitives in this workspace: `position || left || right`
//! (72 bytes, used by the MMR family) and `left || right` (64 bytes, used by
//! the BMT). Both need one full block plus a fixed-layout padding block
//! each. Callers passing one of these shapes as its exact constituent
//! parts (a position and two digests, or two digests) load directly from
//! those parts into vector registers, with no intermediate buffer. Any other
//! shape, or the same shape split into a different part decomposition, falls
//! back to serial hashing.
//!
//! AVX-512 hashes batches of 16 equal-length contiguous messages in independent
//! SIMD lanes, producing the ordinary SHA-256 digest of each message. The batch
//! algorithm uses `commonware_simd` operations shared with emulated profiles.

use super::{DIGEST_LENGTH, Digest, Sha256};
use crate::Hasher;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_simd::{Operation, Simd, dispatch};
#[cfg(feature = "std")]
use std::vec::Vec;

mod batch;
mod constants;
mod pair;

/// The MMR node's position prefix length (an 8-byte big-endian position).
const POSITION_LEN: usize = 8;

/// Independent messages in a full batch.
const X16_LANES: usize = 16;

/// Minimum active messages for the sixteen-lane kernel.
///
/// Uses [ISA-L's shortage cutoff] to keep up to six messages on serial SHA.
///
/// [ISA-L's shortage cutoff]: https://github.com/intel/isa-l_crypto/blob/f22c49aef162d7632bde4f22dc7491b22f0a7fc2/sha256_mb/sha256_job.asm#L38-L46
const MINIMUM_X16_BATCH_LEN: usize = 7;

/// Hash independent messages in input order using one selected backend.
#[inline]
pub(super) fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Vec<Digest> {
    struct HashMany<'a, M>(&'a [M]);

    impl<S: Simd, M: AsRef<[u8]>> Operation<S> for HashMany<'_, M> {
        type Output = Vec<Digest>;

        #[inline(always)]
        fn portable(self, simd: S) -> Self::Output {
            if S::U32_LANES < X16_LANES {
                return self
                    .0
                    .iter()
                    .map(|message| Sha256::hash(&[message.as_ref()]))
                    .collect();
            }

            // Adjacent equal-length runs preserve the kernel's length requirement
            // and the resulting digests' input order.
            let mut digests = Vec::with_capacity(self.0.len());
            for run in self
                .0
                .chunk_by(|left, right| left.as_ref().len() == right.as_ref().len())
            {
                for messages in run.chunks(X16_LANES) {
                    if messages.len() >= MINIMUM_X16_BATCH_LEN {
                        // Spare lanes borrow the first input; only active lanes contribute output.
                        let mut inputs = [messages[0].as_ref(); X16_LANES];
                        for (input, message) in inputs[1..].iter_mut().zip(&messages[1..]) {
                            *input = message.as_ref();
                        }
                        let output = simd.execute(batch::hash::<S>(inputs));
                        digests.extend_from_slice(&output[..messages.len()]);
                    } else {
                        digests.extend(
                            messages
                                .iter()
                                .map(|message| Sha256::hash(&[message.as_ref()])),
                        );
                    }
                }
            }
            digests
        }
    }

    dispatch(HashMany(messages))
}

/// Hash sixteen equal-length messages when the selected backend has enough lanes.
#[cfg(test)]
#[inline]
pub(super) fn hash_x16(messages: [&[u8]; X16_LANES]) -> Option<[Digest; X16_LANES]> {
    let len = messages[0].len();
    if !messages[1..].iter().all(|message| message.len() == len) {
        return None;
    }

    struct HashBatch<'a>([&'a [u8]; X16_LANES]);

    impl<S: Simd> Operation<S> for HashBatch<'_> {
        type Output = Option<[Digest; X16_LANES]>;

        #[inline(always)]
        fn portable(self, simd: S) -> Self::Output {
            if S::U32_LANES < X16_LANES {
                return None;
            }
            Some(simd.execute(batch::hash::<S>(self.0)))
        }
    }

    dispatch(HashBatch(messages))
}

/// Hash two node-length messages, each given as parts, with the pair-hashing
/// kernel for the current CPU.
///
/// Returns `None` when the selected backend has fewer than four lanes, or the
/// messages don't match one of the known node shapes (a position and two
/// digests, or two digests) as their exact constituent parts.
///
/// Inlined aggressively so the shape matching constant-folds at call sites
/// with fixed-shape inputs (e.g. merkle nodes).
#[inline(always)]
pub(super) fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> Option<(Digest, Digest)> {
    struct Pair<'a, const PREFIX: usize> {
        left_pos: &'a [u8; PREFIX],
        left_a: &'a [u8; DIGEST_LENGTH],
        left_b: &'a [u8; DIGEST_LENGTH],
        right_pos: &'a [u8; PREFIX],
        right_a: &'a [u8; DIGEST_LENGTH],
        right_b: &'a [u8; DIGEST_LENGTH],
    }

    impl<S: Simd, const PREFIX: usize> Operation<S> for Pair<'_, PREFIX> {
        type Output = Option<(Digest, Digest)>;

        #[inline(always)]
        fn portable(self, simd: S) -> Self::Output {
            if S::U32_LANES < 4 {
                return None;
            }
            Some(simd.execute(pair::hash::<S, PREFIX>(
                self.left_pos,
                self.left_a,
                self.left_b,
                self.right_pos,
                self.right_a,
                self.right_b,
            )))
        }
    }

    match (left, right) {
        ([left_pos, left_a, left_b], [right_pos, right_a, right_b]) => {
            dispatch(Pair::<POSITION_LEN> {
                left_pos: (*left_pos).try_into().ok()?,
                left_a: (*left_a).try_into().ok()?,
                left_b: (*left_b).try_into().ok()?,
                right_pos: (*right_pos).try_into().ok()?,
                right_a: (*right_a).try_into().ok()?,
                right_b: (*right_b).try_into().ok()?,
            })
        }
        ([left_a, left_b], [right_a, right_b]) => dispatch(Pair::<0> {
            left_pos: &[],
            left_a: (*left_a).try_into().ok()?,
            left_b: (*left_b).try_into().ok()?,
            right_pos: &[],
            right_a: (*right_a).try_into().ok()?,
            right_b: (*right_b).try_into().ok()?,
        }),
        _ => None,
    }
}
