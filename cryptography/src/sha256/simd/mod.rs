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
//! On x86_64, single-message kernels also load one message from its exact
//! parts. They take both node shapes and the two leaf shapes,
//! `position || digest` with an 8-byte MMR or 4-byte BMT position (40 and 36
//! bytes, one block each).
//!
//! AVX-512 hashes batches of 16 equal-length contiguous messages in independent
//! SIMD lanes, producing the ordinary SHA-256 digest of each message.

use super::{DIGEST_LENGTH, Digest};

#[cfg(all(target_arch = "aarch64", any(target_feature = "sha2", feature = "std")))]
mod aarch64;
#[cfg(all(
    target_arch = "x86_64",
    any(
        all(
            target_feature = "avx512f",
            target_feature = "avx512bw",
            target_feature = "avx512vl",
        ),
        all(
            target_feature = "sha",
            target_feature = "avx2",
            target_feature = "ssse3",
            target_feature = "sse4.1",
        ),
        feature = "std",
    ),
))]
mod x86_64;

/// The MMR node's position prefix length (an 8-byte big-endian position).
const POSITION_LEN: usize = 8;

/// The MMR node message length: an 8-byte position and two 32-byte digests.
const MMR_NODE_LEN: usize = POSITION_LEN + 2 * DIGEST_LENGTH;
const _: () = assert!(MMR_NODE_LEN == 72);

/// The BMT node message length: two 32-byte digests (no position).
const BMT_NODE_LEN: usize = 2 * DIGEST_LENGTH;
const _: () = assert!(BMT_NODE_LEN == 64);

/// The MMR leaf message length: an 8-byte position and one 32-byte digest.
#[cfg(target_arch = "x86_64")]
const MMR_LEAF_LEN: usize = POSITION_LEN + DIGEST_LENGTH;
#[cfg(target_arch = "x86_64")]
const _: () = assert!(MMR_LEAF_LEN == 40);

/// The BMT leaf's position prefix length.
#[cfg(target_arch = "x86_64")]
const BMT_POSITION_LEN: usize = 4;

/// The BMT leaf message length: a 4-byte position and one 32-byte digest.
#[cfg(target_arch = "x86_64")]
const BMT_LEAF_LEN: usize = BMT_POSITION_LEN + DIGEST_LENGTH;
#[cfg(target_arch = "x86_64")]
const _: () = assert!(BMT_LEAF_LEN == 36);

/// Independent 32-bit message lanes in a 512-bit vector.
#[cfg(target_arch = "x86_64")]
pub(super) const X16_LANES: usize = 16;

/// Return whether AVX-512 software SHA-256 is available for 16 messages.
#[cfg(target_arch = "x86_64")]
#[inline]
fn supports_hash_x16() -> bool {
    cfg_if::cfg_if! {
        if #[cfg(all(
            target_feature = "avx512f",
            target_feature = "avx512bw",
            target_feature = "avx512vl",
        ))] {
            true
        } else if #[cfg(feature = "std")] {
            std::arch::is_x86_feature_detected!("avx512f")
                && std::arch::is_x86_feature_detected!("avx512bw")
                && std::arch::is_x86_feature_detected!("avx512vl")
        } else {
            false
        }
    }
}

/// Return whether the SHA extensions (SHA-NI) are available.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(super) fn supports_sha_ni() -> bool {
    cfg_if::cfg_if! {
        if #[cfg(feature = "std")] {
            std::arch::is_x86_feature_detected!("sha")
        } else {
            cfg!(target_feature = "sha")
        }
    }
}

/// Return whether every target feature the SHA-NI kernels require is
/// available.
#[cfg(all(
    target_arch = "x86_64",
    any(
        feature = "std",
        all(
            target_feature = "sha",
            target_feature = "avx2",
            target_feature = "ssse3",
            target_feature = "sse4.1",
        ),
    ),
))]
#[inline(always)]
fn supports_sha_ni_kernels() -> bool {
    cfg_if::cfg_if! {
        if #[cfg(all(
            target_feature = "sha",
            target_feature = "avx2",
            target_feature = "ssse3",
            target_feature = "sse4.1",
        ))] {
            true
        } else {
            std::arch::is_x86_feature_detected!("sha")
                && std::arch::is_x86_feature_detected!("avx2")
                && std::arch::is_x86_feature_detected!("ssse3")
                && std::arch::is_x86_feature_detected!("sse4.1")
        }
    }
}

/// Minimum active lanes for an available x16 kernel.
///
/// Uses [ISA-L's shortage cutoffs]: keep up to six messages on SHA-NI, or one
/// message on the software fallback. These are initial tuning choices for the
/// local batch.
///
/// [ISA-L's shortage cutoffs]: https://github.com/intel/isa-l_crypto/blob/f22c49aef162d7632bde4f22dc7491b22f0a7fc2/sha256_mb/sha256_job.asm#L38-L46
#[cfg(target_arch = "x86_64")]
#[inline]
pub(super) fn minimum_x16_batch_len() -> Option<usize> {
    if !supports_hash_x16() {
        return None;
    }
    Some(if supports_sha_ni() { 7 } else { 2 })
}

/// Hash 16 equal-length contiguous messages with AVX-512 software SHA-256.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(super) fn hash_x16(messages: [&[u8]; X16_LANES]) -> Option<[Digest; X16_LANES]> {
    let len = messages[0].len();
    if !supports_hash_x16() || !messages[1..].iter().all(|message| message.len() == len) {
        return None;
    }

    cfg_if::cfg_if! {
        if #[cfg(any(
            feature = "std",
            all(
                target_feature = "avx512f",
                target_feature = "avx512bw",
                target_feature = "avx512vl",
            ),
        ))] {
            // SAFETY: `supports_hash_x16` established every required target
            // feature and equal lengths were established above.
            let digests = unsafe { x86_64::hash_x16_equal(messages) };
            Some(digests)
        } else {
            None
        }
    }
}

/// Hash two node-length messages, each given as parts, with the pair-hashing
/// kernel for the current CPU.
///
/// Returns `None` when the kernel cannot be used: the required CPU features
/// are unavailable, or the messages don't match one of the known node shapes
/// (a position and two digests, or two digests) as their exact constituent
/// parts.
///
/// Inlined aggressively so the shape matching constant-folds at call sites
/// with fixed-shape inputs (e.g. merkle nodes).
#[inline(always)]
pub(super) fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> Option<(Digest, Digest)> {
    match (left, right) {
        ([left_pos, left_left, left_right], [right_pos, right_left, right_right]) => dispatch_mmr(
            (*left_pos).try_into().ok()?,
            (*left_left).try_into().ok()?,
            (*left_right).try_into().ok()?,
            (*right_pos).try_into().ok()?,
            (*right_left).try_into().ok()?,
            (*right_right).try_into().ok()?,
        ),
        ([left_a, left_b], [right_a, right_b]) => dispatch_bmt(
            (*left_a).try_into().ok()?,
            (*left_b).try_into().ok()?,
            (*right_a).try_into().ok()?,
            (*right_b).try_into().ok()?,
        ),
        _ => None,
    }
}

/// Dispatch two node-length messages, given as their constituent parts, to
/// the available kernel.
///
/// `aarch64_kernel`/`x86_64_kernel` name the arch-specific kernel functions
/// to invoke once the required CPU features are confirmed. `args` lists the
/// parts each kernel takes.
macro_rules! define_dispatch {
    ($name:ident, $aarch64_kernel:ident, $x86_64_kernel:ident, ($($arg:ident: $ty:ty),+ $(,)?)) => {
        #[inline(always)]
        fn $name($($arg: $ty),+) -> Option<(Digest, Digest)> {
            cfg_if::cfg_if! {
                if #[cfg(all(target_arch = "aarch64", target_feature = "sha2"))] {
                    // SAFETY: The sha2 target feature is statically enabled.
                    Some(unsafe { aarch64::$aarch64_kernel($($arg),+) })
                } else if #[cfg(all(target_arch = "aarch64", feature = "std"))] {
                    if std::arch::is_aarch64_feature_detected!("sha2") {
                        // SAFETY: The sha2 target feature was just detected.
                        return Some(unsafe { aarch64::$aarch64_kernel($($arg),+) });
                    }
                    None
                } else if #[cfg(all(
                    target_arch = "x86_64",
                    any(
                        feature = "std",
                        all(
                            target_feature = "sha",
                            target_feature = "avx2",
                            target_feature = "ssse3",
                            target_feature = "sse4.1",
                        ),
                    ),
                ))] {
                    if supports_sha_ni_kernels() {
                        // SAFETY: `supports_sha_ni_kernels` established every
                        // required target feature.
                        return Some(unsafe { x86_64::$x86_64_kernel($($arg),+) });
                    }
                    None
                } else {
                    let _ = ($($arg),+);
                    None
                }
            }
        }
    };
}

define_dispatch!(
    dispatch_mmr,
    hash_pair_72,
    hash_pair_72,
    (
        left_pos: &[u8; POSITION_LEN],
        left_left: &[u8; DIGEST_LENGTH],
        left_right: &[u8; DIGEST_LENGTH],
        right_pos: &[u8; POSITION_LEN],
        right_left: &[u8; DIGEST_LENGTH],
        right_right: &[u8; DIGEST_LENGTH],
    )
);
define_dispatch!(
    dispatch_bmt,
    hash_pair_64,
    hash_pair_64,
    (
        left_a: &[u8; DIGEST_LENGTH],
        left_b: &[u8; DIGEST_LENGTH],
        right_a: &[u8; DIGEST_LENGTH],
        right_b: &[u8; DIGEST_LENGTH],
    )
);

/// Hash one merkle-shaped message, given as parts, with the single-message
/// kernel for the current CPU.
///
/// Returns `None` when the required CPU features are unavailable or `parts`
/// is not exactly a position and two digests, two digests, or a position and
/// one digest.
///
/// Inlined so the shape match constant-folds at call sites with fixed-shape
/// inputs.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(super) fn hash_single(parts: &[&[u8]]) -> Option<Digest> {
    match parts {
        [pos, left, right] => dispatch_mmr_node(
            (*pos).try_into().ok()?,
            (*left).try_into().ok()?,
            (*right).try_into().ok()?,
        ),
        [first, digest] => {
            let digest = (*digest).try_into().ok()?;
            match first.len() {
                DIGEST_LENGTH => dispatch_bmt_node((*first).try_into().ok()?, digest),
                POSITION_LEN => dispatch_mmr_leaf((*first).try_into().ok()?, digest),
                BMT_POSITION_LEN => dispatch_bmt_leaf((*first).try_into().ok()?, digest),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Dispatch one merkle-shaped message, given as its constituent parts, to
/// its single-message kernel.
///
/// `kernel` names the x86_64 kernel function to invoke once the required
/// CPU features are confirmed. `args` lists the parts the kernel takes.
#[cfg(target_arch = "x86_64")]
macro_rules! define_single_dispatch {
    ($name:ident, $kernel:ident, ($($arg:ident: $ty:ty),+ $(,)?)) => {
        #[inline(always)]
        fn $name($($arg: $ty),+) -> Option<Digest> {
            cfg_if::cfg_if! {
                if #[cfg(any(
                    feature = "std",
                    all(
                        target_feature = "sha",
                        target_feature = "avx2",
                        target_feature = "ssse3",
                        target_feature = "sse4.1",
                    ),
                ))] {
                    if supports_sha_ni_kernels() {
                        // SAFETY: `supports_sha_ni_kernels` established every
                        // required target feature.
                        return Some(unsafe { x86_64::$kernel($($arg),+) });
                    }
                    None
                } else {
                    let _ = ($($arg),+);
                    None
                }
            }
        }
    };
}

#[cfg(target_arch = "x86_64")]
define_single_dispatch!(
    dispatch_mmr_node,
    hash_72,
    (
        pos: &[u8; POSITION_LEN],
        left: &[u8; DIGEST_LENGTH],
        right: &[u8; DIGEST_LENGTH],
    )
);
#[cfg(target_arch = "x86_64")]
define_single_dispatch!(
    dispatch_bmt_node,
    hash_64,
    (left: &[u8; DIGEST_LENGTH], right: &[u8; DIGEST_LENGTH])
);
#[cfg(target_arch = "x86_64")]
define_single_dispatch!(
    dispatch_mmr_leaf,
    hash_40,
    (pos: &[u8; POSITION_LEN], digest: &[u8; DIGEST_LENGTH])
);
#[cfg(target_arch = "x86_64")]
define_single_dispatch!(
    dispatch_bmt_leaf,
    hash_36,
    (pos: &[u8; BMT_POSITION_LEN], digest: &[u8; DIGEST_LENGTH])
);
