//! Pair-hashing SHA-256 kernels for merkle node messages.
//!
//! Modern SHA extensions (aarch64 SHA2, x86_64 SHA-NI) execute one round per
//! instruction but with multi-cycle latency, so a single message leaves the
//! SHA unit idle between dependent rounds. Interleaving two independent
//! messages fills those latency slots, making progress on both digests at
//! close to the unit's throughput limit.
//!
//! The kernels specialize the merkle node shape (position || left || right,
//! always 72 bytes for SHA-256 digests): one full block plus a compile-time
//! constant padding block each. Other shapes fall back to serial hashing.

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

/// The merkle node message length: an 8-byte position and two 32-byte digests.
const NODE_LEN: usize = 72;

/// Hash two node-length messages, each given as a concatenation of parts,
/// with the pair-hashing kernel for the current CPU.
///
/// Returns `None` when the kernel cannot be used: the required CPU features
/// are unavailable or either message is not exactly [`NODE_LEN`] bytes.
///
/// Inlined aggressively so the length matching constant-folds at call sites
/// with fixed-shape inputs (e.g. merkle nodes), leaving only the out-of-line
/// kernel call.
#[inline(always)]
pub(super) fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> Option<(Digest, Digest)> {
    let left = assemble(left)?;
    let right = assemble(right)?;
    dispatch(&left, &right)
}

/// Concatenate `parts` into a node-length buffer, or `None` if the total
/// length differs.
#[inline(always)]
fn assemble(parts: &[&[u8]]) -> Option<[u8; NODE_LEN]> {
    if parts.iter().map(|part| part.len()).sum::<usize>() != NODE_LEN {
        return None;
    }
    let mut scratch = [0u8; NODE_LEN];
    let mut len = 0;
    for part in parts {
        scratch[len..len + part.len()].copy_from_slice(part);
        len += part.len();
    }
    Some(scratch)
}

/// Dispatch two node-length messages to the available kernel.
#[inline(always)]
fn dispatch(left: &[u8; NODE_LEN], right: &[u8; NODE_LEN]) -> Option<(Digest, Digest)> {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "aarch64", target_feature = "sha2"))] {
            // SAFETY: The sha2 target feature is statically enabled.
            Some(unsafe { aarch64::hash_pair_72(left, right) })
        } else if #[cfg(all(target_arch = "aarch64", feature = "std"))] {
            if std::arch::is_aarch64_feature_detected!("sha2") {
                // SAFETY: The sha2 target feature was just detected.
                return Some(unsafe { aarch64::hash_pair_72(left, right) });
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
            Some(unsafe { x86_64::hash_pair_72(left, right) })
        } else if #[cfg(all(target_arch = "x86_64", feature = "std"))] {
            if std::arch::is_x86_feature_detected!("sha")
                && std::arch::is_x86_feature_detected!("avx2")
                && std::arch::is_x86_feature_detected!("ssse3")
                && std::arch::is_x86_feature_detected!("sse4.1")
            {
                // SAFETY: The required target features were just detected.
                return Some(unsafe { x86_64::hash_pair_72(left, right) });
            }
            None
        } else {
            let _ = (left, right);
            None
        }
    }
}
