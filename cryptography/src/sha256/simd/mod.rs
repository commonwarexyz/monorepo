//! Pair-hashing SHA-256 kernels for merkle node messages.
//!
//! Modern SHA extensions (aarch64 SHA2, x86_64 SHA-NI) execute one round per
//! instruction but with multi-cycle latency, so a single message leaves the
//! SHA unit idle between dependent rounds. Interleaving two independent
//! messages fills those latency slots, making progress on both digests at
//! close to the unit's throughput limit.
//!
//! The kernels specialize the two merkle node shapes used across the
//! Merkle-family primitives in this workspace: `position || left || right`
//! (72 bytes, used by the MMR family) and `left || right` (64 bytes, used by
//! the BMT). Both need one full block plus a compile-time constant padding
//! block each. Other shapes fall back to serial hashing.

use super::Digest;

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

/// The MMR node message length: an 8-byte position and two 32-byte digests.
const MMR_NODE_LEN: usize = 72;

/// The BMT node message length: two 32-byte digests (no position).
const BMT_NODE_LEN: usize = 64;

/// Hash two node-length messages, each given as a concatenation of parts,
/// with the pair-hashing kernel for the current CPU.
///
/// Returns `None` when the kernel cannot be used: the required CPU features
/// are unavailable, or the messages don't match, or don't match one of the
/// known node shapes.
///
/// Inlined aggressively so the length matching constant-folds at call sites
/// with fixed-shape inputs (e.g. merkle nodes), leaving only the out-of-line
/// kernel call.
#[inline(always)]
pub(super) fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> Option<(Digest, Digest)> {
    let len: usize = left.iter().map(|part| part.len()).sum();
    if right.iter().map(|part| part.len()).sum::<usize>() != len {
        return None;
    }
    match len {
        MMR_NODE_LEN => {
            let left = assemble::<MMR_NODE_LEN>(left)?;
            let right = assemble::<MMR_NODE_LEN>(right)?;
            dispatch_mmr(&left, &right)
        }
        BMT_NODE_LEN => {
            let left = assemble::<BMT_NODE_LEN>(left)?;
            let right = assemble::<BMT_NODE_LEN>(right)?;
            dispatch_bmt(&left, &right)
        }
        _ => None,
    }
}

/// Concatenate `parts` into an `N`-byte buffer, or `None` if the total length
/// differs.
#[inline(always)]
fn assemble<const N: usize>(parts: &[&[u8]]) -> Option<[u8; N]> {
    if parts.iter().map(|part| part.len()).sum::<usize>() != N {
        return None;
    }
    let mut scratch = [0u8; N];
    let mut len = 0;
    for part in parts {
        scratch[len..len + part.len()].copy_from_slice(part);
        len += part.len();
    }
    Some(scratch)
}

/// Dispatch two node-length messages to the available kernel.
///
/// `N` is the concrete node message length; `aarch64_kernel`/`x86_64_kernel` name the
/// arch-specific kernel functions to invoke once the required CPU features are confirmed.
macro_rules! define_dispatch {
    ($name:ident, $len:expr, $aarch64_kernel:ident, $x86_64_kernel:ident) => {
        #[inline(always)]
        fn $name(left: &[u8; $len], right: &[u8; $len]) -> Option<(Digest, Digest)> {
            cfg_if::cfg_if! {
                if #[cfg(all(target_arch = "aarch64", target_feature = "sha2"))] {
                    // SAFETY: The sha2 target feature is statically enabled.
                    Some(unsafe { aarch64::$aarch64_kernel(left, right) })
                } else if #[cfg(all(target_arch = "aarch64", feature = "std"))] {
                    if std::arch::is_aarch64_feature_detected!("sha2") {
                        // SAFETY: The sha2 target feature was just detected.
                        return Some(unsafe { aarch64::$aarch64_kernel(left, right) });
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
                    Some(unsafe { x86_64::$x86_64_kernel(left, right) })
                } else if #[cfg(all(target_arch = "x86_64", feature = "std"))] {
                    if std::arch::is_x86_feature_detected!("sha")
                        && std::arch::is_x86_feature_detected!("avx2")
                        && std::arch::is_x86_feature_detected!("ssse3")
                        && std::arch::is_x86_feature_detected!("sse4.1")
                    {
                        // SAFETY: The required target features were just detected.
                        return Some(unsafe { x86_64::$x86_64_kernel(left, right) });
                    }
                    None
                } else {
                    let _ = (left, right);
                    None
                }
            }
        }
    };
}

define_dispatch!(dispatch_mmr, MMR_NODE_LEN, hash_pair_72, hash_pair_72);
define_dispatch!(dispatch_bmt, BMT_NODE_LEN, hash_pair_64, hash_pair_64);
