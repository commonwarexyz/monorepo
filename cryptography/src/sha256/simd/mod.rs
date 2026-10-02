//! SHA-256 kernels for merkle node pairs and independent message batches.
//!
//! Modern SHA extensions (aarch64 SHA2, x86_64 SHA-NI) execute several
//! rounds per instruction but with multi-cycle latency, so a single message
//! leaves the SHA unit idle between dependent instructions. Interleaving two
//! independent messages fills those latency slots, making progress on both
//! digests at close to the unit's throughput limit.
//!
//! The assembly kernels specialize the two merkle node shapes used across the
//! Merkle-family primitives in this workspace: `position || left || right`
//! (72 bytes, used by the MMR family) and `left || right` (64 bytes, used by
//! the BMT). Both need one full block plus a fixed-layout padding block
//! each. The BMT padding block's schedule is the same for every node, so its
//! kernels read it from a precomputed table. Messages of either length given
//! as one part, or as the shape's exact constituent parts (a position and two
//! digests, or two digests), load directly from those parts into vector
//! registers, with no intermediate buffer. Any other pair of equal-length
//! messages, in any part decomposition, uses a generic interleaved kernel. It
//! reads each full block in place when a single part holds it, copies blocks
//! that span parts, and pads the tail on the stack. Messages of different
//! lengths fall back to serial hashing.
//!
//! AVX-512 hashes batches of 16 equal-length contiguous messages in independent
//! SIMD lanes, producing the ordinary SHA-256 digest of each message.

use super::{DIGEST_LENGTH, Digest};

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        mod blocks;
        mod x86_64;
        use x86_64 as kernels;
    } else if #[cfg(any(target_feature = "neon", feature = "std"))] {
        mod aarch64;
        mod blocks;
        use aarch64 as kernels;
    }
}

/// The MMR node's position prefix length (an 8-byte big-endian position).
const POSITION_LEN: usize = 8;

/// The MMR node message length: an 8-byte position and two 32-byte digests.
const MMR_NODE_LEN: usize = POSITION_LEN + 2 * DIGEST_LENGTH;
const _: () = assert!(MMR_NODE_LEN == 72);

/// The BMT node message length: two 32-byte digests (no position).
const BMT_NODE_LEN: usize = 2 * DIGEST_LENGTH;
const _: () = assert!(BMT_NODE_LEN == 64);

/// Independent 32-bit message lanes in a 512-bit vector.
#[cfg(target_arch = "x86_64")]
pub(super) const X16_LANES: usize = 16;

/// Minimum active lanes for an available x16 kernel.
///
/// Uses [ISA-L's shortage cutoffs]: keep up to six messages on SHA-NI, or one
/// message on the software fallback. These are initial tuning choices for the
/// local batch.
///
/// [ISA-L's shortage cutoffs]: https://github.com/intel/isa-l_crypto/blob/f22c49aef162d7632bde4f22dc7491b22f0a7fc2/sha256_mb/sha256_job.asm#L38-L46
#[cfg(target_arch = "x86_64")]
#[inline]
// Feature detection is const only without std.
#[allow(clippy::missing_const_for_fn)]
pub(super) fn minimum_x16_batch_len() -> Option<usize> {
    if !kernels::supports_x16() {
        return None;
    }
    cfg_if::cfg_if! {
        if #[cfg(feature = "std")] {
            let sha = std::arch::is_x86_feature_detected!("sha");
        } else {
            let sha = cfg!(target_feature = "sha");
        }
    }
    Some(if sha { 7 } else { 2 })
}

/// Hash 16 equal-length contiguous messages with AVX-512 software SHA-256.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(super) fn hash_x16(messages: [&[u8]; X16_LANES]) -> Option<[Digest; X16_LANES]> {
    let len = messages[0].len();
    if !kernels::supports_x16() || !messages[1..].iter().all(|message| message.len() == len) {
        return None;
    }

    // SAFETY: `supports_x16` established every required target feature and
    // equal lengths were established above.
    Some(unsafe { kernels::hash_x16_equal(messages) })
}

/// Hash two messages, each given as parts, with the pair-hashing kernel for
/// the current CPU.
///
/// Two messages of one of the known node lengths, both given as one part or
/// both as the shape's exact constituent parts (a position and two digests, or
/// two digests), use that shape's kernel. Any other equal-length messages use
/// the generic kernel.
///
/// Returns `None` when no kernel can be used: the required CPU features are
/// unavailable, or the messages differ in length.
///
/// Inlined aggressively so the shape matching constant-folds at call sites
/// with fixed-shape inputs (e.g. merkle nodes).
#[inline(always)]
pub(super) fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> Option<(Digest, Digest)> {
    let node = match (left, right) {
        ([left_pos, left_left, left_right], [right_pos, right_left, right_right]) => {
            match (
                (*left_pos).try_into(),
                (*left_left).try_into(),
                (*left_right).try_into(),
                (*right_pos).try_into(),
                (*right_left).try_into(),
                (*right_right).try_into(),
            ) {
                (Ok(lp), Ok(ll), Ok(lr), Ok(rp), Ok(rl), Ok(rr)) => {
                    dispatch_mmr(lp, ll, lr, rp, rl, rr)
                }
                _ => None,
            }
        }
        ([left_a, left_b], [right_a, right_b]) => match (
            (*left_a).try_into(),
            (*left_b).try_into(),
            (*right_a).try_into(),
            (*right_b).try_into(),
        ) {
            (Ok(la), Ok(lb), Ok(ra), Ok(rb)) => dispatch_bmt(la, lb, ra, rb),
            _ => None,
        },
        ([left], [right]) => {
            if let (Some((la, lb)), Some((ra, rb))) = (bmt(left), bmt(right)) {
                dispatch_bmt(la, lb, ra, rb)
            } else if let (Some((lp, ll, lr)), Some((rp, rl, rr))) = (mmr(left), mmr(right)) {
                dispatch_mmr(lp, ll, lr, rp, rl, rr)
            } else {
                None
            }
        }
        _ => None,
    };
    node.or_else(|| hash_pair_equal(left, right))
}

/// Split a BMT node-length message into its two digests, or return `None`
/// for any other length.
#[inline(always)]
const fn bmt(message: &[u8]) -> Option<(&[u8; DIGEST_LENGTH], &[u8; DIGEST_LENGTH])> {
    let ([left, right], []) = message.as_chunks::<DIGEST_LENGTH>() else {
        return None;
    };
    Some((left, right))
}

/// Split an MMR node-length message into its position and two digests, or
/// return `None` for any other length.
#[inline(always)]
fn mmr(
    message: &[u8],
) -> Option<(
    &[u8; POSITION_LEN],
    &[u8; DIGEST_LENGTH],
    &[u8; DIGEST_LENGTH],
)> {
    let (position, digests) = message.split_first_chunk()?;
    let (left, right) = bmt(digests)?;
    Some((position, left, right))
}

/// Hash two equal-length messages, each given as parts, with the generic pair
/// kernel for the current CPU.
///
/// Returns `None` when the kernel is unavailable or the messages differ in
/// length. Outlined so it never bloats the inlined node-shape dispatch.
#[inline(never)]
fn hash_pair_equal(left: &[&[u8]], right: &[&[u8]]) -> Option<(Digest, Digest)> {
    let len = message_len(left)?;
    if message_len(right)? != len {
        return None;
    }
    dispatch_equal(left, right, len)
}

/// Return the total length of a message given as parts, or `None` if it
/// overflows.
fn message_len(parts: &[&[u8]]) -> Option<usize> {
    parts
        .iter()
        .try_fold(0usize, |len, part| len.checked_add(part.len()))
}

/// Define `$name`, which runs the kernel `$kernel` for the current CPU on its
/// arguments, or returns `None` when the kernel's instructions are
/// unavailable.
macro_rules! define_dispatch {
    ($name:ident, $kernel:ident, ($($arg:ident: $ty:ty),+ $(,)?) -> $output:ty) => {
        #[inline(always)]
        fn $name($($arg: $ty),+) -> Option<$output> {
            cfg_if::cfg_if! {
                if #[cfg(any(target_arch = "x86_64", target_feature = "neon", feature = "std"))] {
                    if kernels::supports_sha() {
                        // SAFETY: `supports_sha` established the kernel's
                        // target features.
                        return Some(unsafe { kernels::$kernel($($arg),+) });
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
    (
        left_pos: &[u8; POSITION_LEN],
        left_left: &[u8; DIGEST_LENGTH],
        left_right: &[u8; DIGEST_LENGTH],
        right_pos: &[u8; POSITION_LEN],
        right_left: &[u8; DIGEST_LENGTH],
        right_right: &[u8; DIGEST_LENGTH],
    ) -> (Digest, Digest)
);
define_dispatch!(
    dispatch_bmt,
    hash_pair_64,
    (
        left_a: &[u8; DIGEST_LENGTH],
        left_b: &[u8; DIGEST_LENGTH],
        right_a: &[u8; DIGEST_LENGTH],
        right_b: &[u8; DIGEST_LENGTH],
    ) -> (Digest, Digest)
);
define_dispatch!(
    dispatch_equal,
    hash_pair_equal,
    (left: &[&[u8]], right: &[&[u8]], len: usize) -> (Digest, Digest)
);
