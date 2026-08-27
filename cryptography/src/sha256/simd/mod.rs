//! Pair-hashing SHA-256 kernels for merkle node messages.
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

use super::{DIGEST_LENGTH, Digest};

#[cfg(all(target_arch = "aarch64", any(target_feature = "sha2", feature = "std")))]
mod aarch64;
#[cfg(all(
    target_arch = "x86_64",
    any(
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
                    target_feature = "sha",
                    target_feature = "avx2",
                    target_feature = "ssse3",
                    target_feature = "sse4.1",
                ))] {
                    // SAFETY: The required target features are statically enabled.
                    Some(unsafe { x86_64::$x86_64_kernel($($arg),+) })
                } else if #[cfg(all(target_arch = "x86_64", feature = "std"))] {
                    if std::arch::is_x86_feature_detected!("sha")
                        && std::arch::is_x86_feature_detected!("avx2")
                        && std::arch::is_x86_feature_detected!("ssse3")
                        && std::arch::is_x86_feature_detected!("sse4.1")
                    {
                        // SAFETY: The required target features were just detected.
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
