//! SHA-256 implementation of the `Hasher` trait.
//!
//! This implementation uses the `sha2` crate to generate SHA-256 digests.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Hasher, Sha256};
//!
//! // Hash data in a single shot (fastest path)
//! let digest = Sha256::hash(&[b"hello,", b"world!"]);
//! println!("digest: {:?}", digest);
//!
//! // Or stream data incrementally
//! let mut hasher = Sha256::default();
//! hasher.update(b"hello,");
//! hasher.update(b"world!");
//! let (_hasher, digest) = hasher.finalize();
//! println!("digest: {:?}", digest);
//!
//! // Hash independent messages with SIMD acceleration when available.
//! // Batching is most effective for messages of the same length.
//! let messages: [[u8; 32]; 16] = core::array::from_fn(|lane| [lane as u8; 32]);
//! let digests = Sha256::hash_many(&messages);
//! assert_eq!(digests[3], Sha256::hash(&[messages[3].as_slice()]));
//! ```

use crate::Hasher;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(all(
    not(feature = "std"),
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
use alloc::vec::Vec;
use bytes::BufMut;
use commonware_codec::{
    Buf, DecodeExt, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write,
};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_utils::{Array, Span};
use core::{
    fmt::{Debug, Display},
    ops::Deref,
};
use rand_core::CryptoRng;
use sha2::{Digest as _, Sha256 as ISha256, block_api::compress256};
use zeroize::Zeroize;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod simd;

/// Re-export `sha2::Sha256` as `CoreSha256` for external use if needed.
pub type CoreSha256 = ISha256;

const DIGEST_LENGTH: usize = 32;

/// The SHA-256 block size in bytes.
const BLOCK_LENGTH: usize = 64;

/// Maximum message length, in bytes, that the fixed-size fast path can handle.
///
/// SHA-256 padding appends a single `0x80` byte and an 8-byte length suffix.
/// Within two blocks (128 bytes), at most `128 - 9 = 119` bytes of message can
/// be hashed without spilling into a third block, which is the range we
/// specialize for.
const MAX_FIXED: usize = 2 * BLOCK_LENGTH - 9;

/// The SHA-256 initial hash values (FIPS 180-4, §5.3.3).
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Serialize the SHA-256 state words into a big-endian digest.
#[inline]
fn digest_from_state(state: [u32; 8]) -> [u8; DIGEST_LENGTH] {
    let mut out = [0u8; DIGEST_LENGTH];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *chunk = word.to_be_bytes();
    }
    out
}

/// Pad and compress `scratch[..len]` (where `len <= MAX_FIXED`) directly from
/// the IV, assuming `scratch[len..]` is already zeroed (i.e. fresh scratch).
///
/// This avoids the streaming hasher's buffering and the redundant zero-fill of
/// the padding region, which is the bulk of the one-shot speedup.
#[inline]
fn finalize_fixed_fresh(scratch: &mut [u8; 2 * BLOCK_LENGTH], len: usize) -> [u8; DIGEST_LENGTH] {
    assert!(len <= MAX_FIXED);
    let bit_len = ((len as u64) * 8).to_be_bytes();
    scratch[len] = 0x80;
    let mut state = IV;
    if len < BLOCK_LENGTH - 8 {
        // Message + padding fit in a single block.
        scratch[BLOCK_LENGTH - 8..BLOCK_LENGTH].copy_from_slice(&bit_len);
        let (blocks, _) = scratch[..BLOCK_LENGTH].as_chunks::<BLOCK_LENGTH>();
        compress256(&mut state, blocks);
    } else {
        // Padding spills into a second block.
        scratch[2 * BLOCK_LENGTH - 8..].copy_from_slice(&bit_len);
        let (blocks, _) = scratch.as_chunks::<BLOCK_LENGTH>();
        compress256(&mut state, blocks);
    }
    digest_from_state(state)
}

/// Specialize the hot merkle shapes: constant offsets let the compiler inline
/// the copies and drop the runtime-length bookkeeping. The general case is
/// outlined into [`hash_general`] so this stays small enough to inline.
#[inline(always)]
fn hash_specialized(parts: &[&[u8]]) -> Digest {
    match parts {
        [p, l, r] if p.len() == 8 && l.len() == 32 && r.len() == 32 => {
            let mut scratch = [0u8; 2 * BLOCK_LENGTH];
            scratch[..8].copy_from_slice(p);
            scratch[8..40].copy_from_slice(l);
            scratch[40..72].copy_from_slice(r);
            Digest(finalize_fixed_fresh(&mut scratch, 72))
        }
        [a, b] if a.len() == 32 && b.len() == 32 => {
            let mut scratch = [0u8; 2 * BLOCK_LENGTH];
            scratch[..32].copy_from_slice(a);
            scratch[32..64].copy_from_slice(b);
            Digest(finalize_fixed_fresh(&mut scratch, 64))
        }
        [p, d] if p.len() == 8 && d.len() == 32 => {
            let mut scratch = [0u8; 2 * BLOCK_LENGTH];
            scratch[..8].copy_from_slice(p);
            scratch[8..40].copy_from_slice(d);
            Digest(finalize_fixed_fresh(&mut scratch, 40))
        }
        [p, d] if p.len() == 4 && d.len() == 32 => {
            let mut scratch = [0u8; 2 * BLOCK_LENGTH];
            scratch[..4].copy_from_slice(p);
            scratch[4..36].copy_from_slice(d);
            Digest(finalize_fixed_fresh(&mut scratch, 36))
        }
        _ => hash_general(parts),
    }
}

/// General-purpose assembly + streaming fallback for shapes that miss the
/// specialized arms (e.g. single-part messages and variable-length leaves).
/// Outlined so it never bloats callers.
#[inline(never)]
fn hash_general(parts: &[&[u8]]) -> Digest {
    let mut scratch = [0u8; 2 * BLOCK_LENGTH];
    let mut len = 0usize;
    let mut parts = parts.iter();
    loop {
        match parts.next() {
            Some(part) if len + part.len() <= MAX_FIXED => {
                scratch[len..len + part.len()].copy_from_slice(part);
                len += part.len();
            }
            Some(part) => {
                let mut hasher = ISha256::new();
                hasher.update(&scratch[..len]);
                hasher.update(part);
                for part in parts {
                    hasher.update(part);
                }
                let array: [u8; DIGEST_LENGTH] = hasher.finalize().into();
                return Digest(array);
            }
            None => break,
        }
    }
    Digest(finalize_fixed_fresh(&mut scratch, len))
}

/// SHA-256 hasher.
#[derive(Debug, Default)]
pub struct Sha256 {
    hasher: ISha256,
}

impl Sha256 {
    /// Convenience function for testing that creates an easily recognizable digest by repeating a
    /// single byte.
    pub fn fill(b: u8) -> <Self as Hasher>::Digest {
        <Self as Hasher>::Digest::decode(vec![b; DIGEST_LENGTH]).unwrap()
    }
}

impl Hasher for Sha256 {
    type Digest = Digest;

    #[inline]
    fn hash(parts: &[&[u8]]) -> Self::Digest {
        hash_specialized(parts)
    }

    #[inline]
    fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if let Some(pair) = simd::hash_pair(left, right) {
            return pair;
        }
        (Self::hash(left), Self::hash(right))
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Vec<Self::Digest> {
        simd::hash_many(messages)
    }

    #[cfg(target_arch = "x86_64")]
    fn hash_many_parts<const P: usize>(messages: &[[&[u8]; P]]) -> Vec<Self::Digest> {
        simd::hash_many_parts(messages).unwrap_or_else(|| crate::hash_pairs::<Self, P>(messages))
    }

    #[inline]
    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.hasher.update(message);
        self
    }

    #[inline]
    fn finalize(mut self) -> (Self, Self::Digest) {
        let finalized = self.hasher.finalize_reset();
        let array: [u8; DIGEST_LENGTH] = finalized.into();
        (self, Digest(array))
    }
}

/// Digest of a SHA-256 hashing operation.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, FixedArray)]
#[fixed_array(infallible)]
#[repr(transparent)]
pub struct Digest(pub [u8; DIGEST_LENGTH]);

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Digest {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate random bytes and compute their Sha256 hash
        let len = u.int_in_range(0..=256)?;
        let data = u.bytes(len)?;
        Ok(Sha256::hash(&[data]))
    }
}

impl Write for Digest {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Digest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let array = <[u8; DIGEST_LENGTH]>::read(buf)?;
        Ok(Self(array))
    }
}

impl FixedSize for Digest {
    const SIZE: usize = DIGEST_LENGTH;
}

impl Span for Digest {}

impl Array for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Digest {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.0))
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.0))
    }
}

impl crate::Digest for Digest {
    const EMPTY: Self = Self([0u8; DIGEST_LENGTH]);
}

impl Random for Digest {
    fn random(mut rng: impl CryptoRng) -> Self {
        let mut array = [0u8; DIGEST_LENGTH];
        rng.fill_bytes(&mut array);
        Self(array)
    }
}

impl Zeroize for Digest {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Copying, DecodeExt, Encode};
    use commonware_utils::TestRng;
    use rand::Rng as _;

    const HELLO_DIGEST: [u8; DIGEST_LENGTH] = commonware_formatting::hex!(
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );

    /// Anchor the streaming and one-shot paths to a known SHA-256 digest,
    /// which the differential fuzz tests (comparing paths against each
    /// other) cannot do.
    #[test]
    fn test_sha256() {
        let msg = b"hello world";

        // Generate hash via streaming
        let mut hasher = Sha256::default();
        hasher.update(msg);
        let (_, digest) = hasher.finalize();
        assert!(Digest::decode(Copying(&digest)).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);

        // Test one-shot hasher
        let hash = Sha256::hash(&[msg]);
        assert_eq!(hash.as_ref(), HELLO_DIGEST);

        // Test multi-part one-shot hasher
        let hash = Sha256::hash(&[b"hello", b" world"]);
        assert_eq!(hash.as_ref(), HELLO_DIGEST);
    }

    /// Exhaustively sweep every total length across the block-padding and
    /// `MAX_FIXED` boundaries, checking the one-shot path against the
    /// streaming implementation. Fuzzing only hits specific off-by-one
    /// lengths probabilistically, while this sweep guarantees them all.
    #[test]
    fn test_sha256_hash_parts_boundaries() {
        for total in 0..=300usize {
            let data: Vec<u8> = (0..total).map(|i| i as u8).collect();
            // Split into a few parts of varying sizes.
            let mid = total / 3;
            let parts: [&[u8]; 3] = [&data[..mid], &data[mid..2 * mid], &data[2 * mid..]];

            let oneshot = Sha256::hash(&parts);

            let mut hasher = Sha256::default();
            for part in &parts {
                hasher.update(part);
            }
            let (_, streamed) = hasher.finalize();

            assert_eq!(oneshot, streamed, "mismatch for total={total}");
        }
    }

    /// Pin every specialized fast-path arm against the streaming implementation.
    #[test]
    fn test_sha256_hash_specialized_arms() {
        let data: Vec<u8> = (0u8..72).collect();
        let shapes: [&[&[u8]]; 4] = [
            &[&data[..8], &data[8..40], &data[40..72]],
            &[&data[..32], &data[32..64]],
            &[&data[..8], &data[8..40]],
            &[&data[..4], &data[4..36]],
        ];
        for parts in shapes {
            let oneshot = Sha256::hash(parts);

            let mut hasher = Sha256::default();
            for part in parts {
                hasher.update(part);
            }
            let (_, streamed) = hasher.finalize();

            assert_eq!(oneshot, streamed, "mismatch for shape {parts:?}");
        }
    }

    #[test]
    fn test_sha256_len() {
        assert_eq!(Digest::SIZE, DIGEST_LENGTH);
    }

    /// Deterministically exercise the pair (assembly) kernel with the MMR
    /// node shape (position || left || right) that motivates it, regardless
    /// of what the fuzz generators happen to sample.
    #[test]
    fn test_hash_pair_mmr_node_shape_matches_streaming() {
        fn node(position: u64, fill: u8) -> Vec<Vec<u8>> {
            vec![
                position.to_be_bytes().to_vec(),
                vec![fill; 32],
                vec![fill + 1; 32],
            ]
        }
        crate::fuzz::Plan::<Sha256>::new(node(42, 0x11), node(43, 0x33)).run();
    }

    /// Deterministically exercise the pair (assembly) kernel with the BMT
    /// node shape (left || right, no position) that motivates it, regardless
    /// of what the fuzz generators happen to sample.
    #[test]
    fn test_hash_pair_bmt_node_shape_matches_streaming() {
        fn assert_pair(left: [&[u8]; 2], right: [&[u8]; 2]) {
            let expected = |parts: &[&[u8]]| {
                let mut hasher = Sha256::default();
                for part in parts {
                    hasher.update(part);
                }
                hasher.finalize().1
            };
            let (left_digest, right_digest) = Sha256::hash_pair(&left, &right);
            let expected_left = expected(&left);
            let expected_right = expected(&right);
            assert_eq!(Sha256::hash(&left), expected_left);
            assert_eq!(Sha256::hash(&right), expected_right);
            assert_eq!(left_digest, expected_left);
            assert_eq!(right_digest, expected_right);
        }

        let zero = [0u8; 32];
        let ff = [0xff; 32];
        let ascending: [u8; 32] = core::array::from_fn(|i| i as u8);
        let descending: [u8; 32] = core::array::from_fn(|i| 0xff - i as u8);
        assert_pair([&zero, &zero], [&zero, &zero]);
        assert_pair([&ff, &ff], [&ff, &ff]);
        assert_pair([&ascending, &descending], [&ff, &zero]);

        let backing: Vec<u8> = (0..96).map(|i| i as u8).collect();
        assert_pair(
            [&backing[1..33], &backing[17..49]],
            [&backing[2..34], &backing[18..50]],
        );
    }

    /// Return `len` random bytes, distinct per `seed`.
    fn message(len: usize, seed: u64) -> Vec<u8> {
        let mut message = vec![0; len];
        TestRng::new(seed).fill_bytes(&mut message);
        message
    }

    /// Return `message` in several part decompositions: whole, split at
    /// block and padding boundaries, with an empty part, and in 7-byte parts
    /// that put block boundaries inside parts.
    fn decompositions(message: &[u8]) -> Vec<Vec<&[u8]>> {
        let len = message.len();
        let mut decompositions = vec![vec![message], message.chunks(7).collect()];
        for split in [0, 1, 8, 55, 63, 64, 65, len / 2, len] {
            let split = split.min(len);
            let (head, tail) = message.split_at(split);
            decompositions.push(vec![head, tail]);
            decompositions.push(vec![head, &[], tail]);
        }
        decompositions
    }

    /// Check the generic pair kernel against one-shot hashing for
    /// equal-length messages across the block and padding boundaries, with
    /// the two messages split into different parts.
    #[test]
    fn test_hash_pair_equal_lengths_match_hash() {
        for len in (0..=300).chain([1000, 4099]) {
            let left = message(len, 1);
            let right = message(len, 2);
            let expected = (Sha256::hash(&[&left]), Sha256::hash(&[&right]));
            let left_parts = decompositions(&left);
            let right_parts = decompositions(&right);
            for (index, left) in left_parts.iter().enumerate() {
                let right = &right_parts[(index + 1) % right_parts.len()];
                assert_eq!(Sha256::hash_pair(left, right), expected, "len={len}");
            }
        }

        // Messages of different lengths hash individually.
        let left = message(100, 1);
        let right = message(101, 2);
        assert_eq!(
            Sha256::hash_pair(&[&left], &[&right]),
            (Sha256::hash(&[&left]), Sha256::hash(&[&right]))
        );
    }

    /// Check batched hashing of multi-part messages against one-shot hashing
    /// for the merkle node and leaf shapes, at batch counts around the x16
    /// cutoff and lane count, and for runs of mixed lengths.
    #[test]
    fn test_hash_many_parts_matches_hash() {
        fn check<const P: usize>(lens: [usize; P], count: usize, run: usize) {
            let messages: Vec<[Vec<u8>; P]> = (0..count)
                .map(|index| {
                    // Every `run` messages, grow the last part by one byte.
                    let grow = index / run;
                    core::array::from_fn(|part| {
                        let len = lens[part] + if part == P - 1 { grow } else { 0 };
                        message(len, (index * P + part) as u64)
                    })
                })
                .collect();
            let parts: Vec<[&[u8]; P]> = messages
                .iter()
                .map(|message| message.each_ref().map(Vec::as_slice))
                .collect();
            let expected: Vec<_> = parts.iter().map(|parts| Sha256::hash(parts)).collect();
            assert_eq!(
                Sha256::hash_many_parts(&parts),
                expected,
                "lens={lens:?} count={count} run={run}"
            );
        }

        for count in [0, 1, 2, 3, 9, 10, 11, 15, 16, 17, 25, 26, 31, 32, 33, 40] {
            for run in [1, 5, usize::MAX] {
                check([8, 32, 32], count, run);
                check([32, 32], count, run);
                check([8, 32], count, run);
                check([4, 32], count, run);
                check([8, 100], count, run);
                check([8, 1000, 3], count, run);
            }
        }
    }

    #[test]
    fn test_hash_many_boundaries_match_individual_hashes() {
        for len in (0..=129).chain([255, 256, 1024, 12_634, 50_534]) {
            let messages: [Vec<u8>; 33] = core::array::from_fn(|lane| {
                (0..len)
                    .map(|i| (i as u8).wrapping_add(lane as u8))
                    .collect()
            });
            let refs = messages.each_ref().map(Vec::as_slice);
            for count in [0, 1, 2, 6, 7, 9, 10, 15, 16, 17, 25, 26, 31, 32, 33] {
                let refs = &refs[..count];
                let expected = refs
                    .iter()
                    .map(|&message| Sha256::hash(&[message]))
                    .collect::<Vec<_>>();
                assert_eq!(Sha256::hash_many(refs), expected);
            }
        }

        let messages: [Vec<u8>; 16] = core::array::from_fn(|lane| vec![lane as u8; 64]);
        let mut refs = messages.each_ref().map(Vec::as_slice);
        refs[9] = &messages[9][..63];
        let expected = refs
            .iter()
            .map(|&message| Sha256::hash(&[message]))
            .collect::<Vec<_>>();
        assert_eq!(Sha256::hash_many(&refs), expected);
        #[cfg(target_arch = "x86_64")]
        assert!(simd::hash_x16(refs).is_none());
    }

    #[test]
    fn test_hash_many_aliased_unaligned_inputs_match_individual_hashes() {
        let backing: Vec<u8> = (0..160).map(|i| i as u8).collect();
        let messages: [&[u8]; 16] = core::array::from_fn(|lane| &backing[lane..lane + 129]);
        let expected = messages
            .iter()
            .map(|&message| Sha256::hash(&[message]))
            .collect::<Vec<_>>();
        for count in 1..=messages.len() {
            assert_eq!(Sha256::hash_many(&messages[..count]), expected[..count]);
        }

        let message = &backing[1..130];
        let messages = [message; 16];
        let expected = messages
            .iter()
            .map(|&message| Sha256::hash(&[message]))
            .collect::<Vec<_>>();
        assert_eq!(Sha256::hash_many(&messages), expected);
    }

    #[test]
    fn test_codec() {
        let msg = b"hello world";
        let mut hasher = Sha256::default();
        hasher.update(msg);
        let (_, digest) = hasher.finalize();

        let encoded = digest.encode();
        assert_eq!(encoded.len(), DIGEST_LENGTH);
        assert_eq!(encoded, digest.as_ref());

        let decoded = Digest::decode(encoded).unwrap();
        assert_eq!(digest, decoded);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Digest>,
        }
    }
}
