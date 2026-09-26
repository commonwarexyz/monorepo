//! BLAKE3 implementation of the [Hasher] trait.
//!
//! Single messages use the [blake3] crate. [Hasher::hash_with] splits messages
//! larger than 64 KiB along BLAKE3's tree and hashes the subtrees across the
//! given strategy.
//!
//! With AVX2 on x86_64, and on aarch64, equal-length node pairs of up to 128
//! bytes use a two-message kernel. With AVX2 or AVX-512 on x86_64, and NEON on
//! aarch64, runs of equal-length messages in [Hasher::hash_many] and
//! [Hasher::hash_many_parts] use SIMD kernels with one message per vector lane.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Hasher, blake3::Blake3};
//!
//! // Hash data in a single shot
//! let digest = Blake3::hash(&[b"hello,", b"world!"]);
//! println!("digest: {:?}", digest);
//!
//! // Or stream data incrementally
//! let mut hasher = Blake3::default();
//! hasher.update(b"hello,");
//! hasher.update(b"world!");
//! let (_hasher, digest) = hasher.finalize();
//! println!("digest: {:?}", digest);
//!
//! // Hash independent messages with SIMD acceleration when available.
//! // Batching is most effective for messages of the same length.
//! let messages: [[u8; 32]; 16] = core::array::from_fn(|lane| [lane as u8; 32]);
//! let digests = Blake3::hash_many(&messages);
//! assert_eq!(digests[3], Blake3::hash(&[messages[3].as_slice()]));
//! ```

use crate::Hasher;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use blake3::{
    Hash,
    hazmat::{
        ChainingValue, HasherExt as _, Mode, left_subtree_len, merge_subtrees_non_root,
        merge_subtrees_root,
    },
};
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_utils::{Array, Span};
use core::{
    fmt::{Debug, Display},
    ops::Deref,
};
use rand_core::CryptoRng;
use zeroize::Zeroize;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod simd;

/// Re-export [blake3::Hasher] as `CoreBlake3` for external use if needed.
pub type CoreBlake3 = blake3::Hasher;

const DIGEST_LENGTH: usize = blake3::OUT_LEN;

/// Largest multi-part message, in bytes, that is concatenated into a stack
/// buffer before hashing (two blocks, which covers the merkle node shapes).
const PAIR_LEN: usize = 2 * blake3::BLOCK_LEN;

/// Largest subtree, in bytes, that [`Hasher::hash_with`] hashes as one task.
///
/// Each task still hashes its chunks in SIMD lanes, so tasks only need to be
/// large enough to amortize the strategy's scheduling cost.
const TASK_LEN: usize = 64 * 1024;

/// Hash the two children of the `len`-byte node at `offset` across `strategy`.
///
/// `parts` holds the node's bytes and starts at byte `base` of the message.
/// The node must be a nonempty node of the message's BLAKE3 tree larger than
/// one chunk, such as one reached by splitting with `left_subtree_len`.
fn children(
    strategy: &impl Strategy,
    parts: &[&[u8]],
    base: usize,
    offset: usize,
    len: usize,
) -> (ChainingValue, ChainingValue) {
    let left = left_subtree_len(len as u64) as usize;
    let split = offset + left;

    // The right child starts in the first part that ends after `split`.
    let mut start = base;
    let mut index = 0;
    for (i, part) in parts.iter().enumerate() {
        if start + part.len() > split {
            index = i;
            break;
        }
        start += part.len();
    }
    strategy.join(
        || subtree(strategy, &parts[..=index], base, offset, left),
        || subtree(strategy, &parts[index..], start, split, len - left),
    )
}

/// Hash the `len`-byte node at `offset`, splitting it across `strategy` until
/// each task fits in [`TASK_LEN`].
///
/// `parts` holds the node's bytes and starts at byte `base` of the message.
/// The node must be a nonempty node of the message's BLAKE3 tree.
fn subtree(
    strategy: &impl Strategy,
    parts: &[&[u8]],
    base: usize,
    offset: usize,
    len: usize,
) -> ChainingValue {
    if len > TASK_LEN {
        let (left, right) = children(strategy, parts, base, offset, len);
        return merge_subtrees_non_root(&left, &right, Mode::Hash);
    }

    let mut hasher = CoreBlake3::new();
    hasher.set_input_offset(offset as u64);
    let end = offset + len;
    let mut start = base;
    for part in parts {
        if start >= end {
            break;
        }
        let (low, high) = (offset.max(start), end.min(start + part.len()));
        if low < high {
            hasher.update(&part[low - start..high - start]);
        }
        start += part.len();
    }
    hasher.finalize_non_root()
}

/// Copy the concatenation of `parts` into a zero-padded buffer, returning
/// `None` if it exceeds [`PAIR_LEN`] bytes.
#[inline]
fn gather(parts: &[&[u8]]) -> Option<([u8; PAIR_LEN], usize)> {
    let mut buffer = [0u8; PAIR_LEN];
    let mut len = 0;
    for part in parts {
        buffer.get_mut(len..len + part.len())?.copy_from_slice(part);
        len += part.len();
    }
    Some((buffer, len))
}

/// BLAKE3 hasher.
#[derive(Debug, Default)]
pub struct Blake3 {
    hasher: CoreBlake3,
}

impl Hasher for Blake3 {
    type Digest = Digest;

    #[inline]
    fn hash(parts: &[&[u8]]) -> Self::Digest {
        if let [part] = parts {
            return blake3::hash(part).into();
        }
        if let Some((buffer, len)) = gather(parts) {
            return blake3::hash(&buffer[..len]).into();
        }
        let mut hasher = CoreBlake3::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }

    fn hash_with(strategy: &impl Strategy, parts: &[&[u8]]) -> Self::Digest {
        // A total that overflows `usize` (aliased parts on 32-bit targets) is
        // hashed serially, which counts bytes in a `u64`.
        let len = parts
            .iter()
            .try_fold(0usize, |len, part| len.checked_add(part.len()));
        match len {
            Some(len) if len > TASK_LEN => {
                let (left, right) = children(strategy, parts, 0, 0, len);
                merge_subtrees_root(&left, &right, Mode::Hash).into()
            }
            _ => Self::hash(parts),
        }
    }

    #[inline]
    fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if let Some(pair) = simd::hash_pair(left, right) {
            return pair;
        }
        (Self::hash(left), Self::hash(right))
    }

    fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Vec<Self::Digest> {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if let Some(digests) = simd::hash_many(messages) {
            return digests;
        }
        messages
            .iter()
            .map(|message| blake3::hash(message.as_ref()).into())
            .collect()
    }

    fn hash_many_parts<const P: usize>(messages: &[[&[u8]; P]]) -> Vec<Self::Digest> {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if let Some(digests) = simd::hash_many_parts(messages) {
            return digests;
        }
        crate::hash_pairs::<Self, P>(messages)
    }

    #[inline]
    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.hasher.update(message);
        self
    }

    #[inline]
    fn finalize(mut self) -> (Self, Self::Digest) {
        let digest = self.hasher.finalize().into();
        self.hasher.reset();
        (self, digest)
    }
}

/// Digest of a BLAKE3 hashing operation.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, FixedArray)]
#[fixed_array(infallible)]
#[repr(transparent)]
pub struct Digest(pub [u8; DIGEST_LENGTH]);

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Digest {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate random bytes and compute their Blake3 hash
        let len = u.int_in_range(0..=256)?;
        let data = u.bytes(len)?;
        Ok(Blake3::hash(&[data]))
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

impl From<Hash> for Digest {
    fn from(value: Hash) -> Self {
        Self(value.into())
    }
}

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
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
    );

    /// Return `len` random bytes, distinct per `seed`.
    fn random(len: usize, seed: u64) -> Vec<u8> {
        let mut bytes = vec![0; len];
        TestRng::new(seed).fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn test_blake3() {
        let msg = b"hello world";

        // Generate initial hash
        let mut hasher = Blake3::default();
        hasher.update(msg);
        let (hasher, digest) = hasher.finalize();
        assert!(Digest::decode(Copying(&digest)).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);

        // Reuse the reset hasher
        let mut hasher = hasher;
        hasher.update(msg);
        let (_, digest) = hasher.finalize();
        assert!(Digest::decode(Copying(&digest)).is_ok());
        assert_eq!(digest.as_ref(), HELLO_DIGEST);

        // Test one-shot hasher
        let hash = Blake3::hash(&[msg]);
        assert_eq!(hash.as_ref(), HELLO_DIGEST);

        // Test multi-part one-shot hasher
        let hash = Blake3::hash(&[b"hello", b" world"]);
        assert_eq!(hash.as_ref(), HELLO_DIGEST);
    }

    /// Reference digest: the concatenated parts through the crate's hasher.
    fn reference(parts: &[&[u8]]) -> Digest {
        blake3::Hasher::new()
            .update(&parts.concat())
            .finalize()
            .into()
    }

    #[test]
    fn test_blake3_hash_parts_boundaries() {
        for total in (0..=300usize).chain([1023, 1024, 1025, 2049]) {
            let data: Vec<u8> = (0..total).map(|i| i as u8).collect();
            let mid = total / 3;
            let parts: [&[u8]; 3] = [&data[..mid], &data[mid..2 * mid], &data[2 * mid..]];
            assert_eq!(Blake3::hash(&parts), reference(&parts), "total={total}");
            assert_eq!(Blake3::hash(&[&data]), reference(&[&data]), "total={total}");
        }
        assert_eq!(Blake3::hash(&[]), reference(&[]));
        assert_eq!(Blake3::hash(&[&[], &[]]), reference(&[]));
    }

    /// Deterministically exercise the pair kernel with the MMR node shape
    /// (position || left || right).
    #[test]
    fn test_hash_pair_mmr_node_shape_matches_streaming() {
        fn node(position: u64, fill: u8) -> Vec<Vec<u8>> {
            vec![
                position.to_be_bytes().to_vec(),
                vec![fill; 32],
                vec![fill + 1; 32],
            ]
        }
        crate::fuzz::Plan::<Blake3>::new(node(42, 0x11), node(43, 0x33)).run();
    }

    /// Deterministically exercise the pair kernel with the BMT node shape
    /// (left || right).
    #[test]
    fn test_hash_pair_bmt_node_shape_matches_streaming() {
        let zero = [0u8; 32];
        let ff = [0xff; 32];
        let ascending: [u8; 32] = core::array::from_fn(|i| i as u8);
        let backing: Vec<u8> = (0..96).map(|i| i as u8).collect();
        for (left, right) in [
            ([&zero[..], &zero[..]], [&zero[..], &zero[..]]),
            ([&ff[..], &ff[..]], [&ff[..], &ff[..]]),
            ([&ascending[..], &ff[..]], [&ff[..], &zero[..]]),
            (
                [&backing[1..33], &backing[17..49]],
                [&backing[2..34], &backing[18..50]],
            ),
        ] {
            assert_eq!(
                Blake3::hash_pair(&left, &right),
                (reference(&left), reference(&right))
            );
        }
    }

    #[test]
    fn test_hash_pair_lengths_match_streaming() {
        let data: Vec<u8> = (0..1100).map(|i| (i as u8).wrapping_mul(7)).collect();
        for len in (0..=2 * PAIR_LEN).chain([1024, 1025]) {
            let left = &data[..len];
            let right = &data[1..=len];
            let split = len / 2;
            let (left_digest, right_digest) =
                Blake3::hash_pair(&[&left[..split], &left[split..]], &[right]);
            assert_eq!(left_digest, reference(&[left]), "len={len}");
            assert_eq!(right_digest, reference(&[right]), "len={len}");

            // Unequal lengths fall back to independent hashes.
            let (left_digest, right_digest) = Blake3::hash_pair(&[left], &[&data[..=len]]);
            assert_eq!(left_digest, reference(&[left]), "len={len}");
            assert_eq!(right_digest, reference(&[&data[..=len]]), "len={len}");
        }
    }

    #[test]
    fn test_hash_many_boundaries_match_individual_hashes() {
        let lengths = (0..=129).chain([
            191, 192, 193, 1023, 1024, 1025, 2048, 2049, 3072, 4097, 16_384, 17_409,
        ]);
        for len in lengths {
            // Bytes do not repeat across chunks, so a kernel reading the wrong
            // chunk, block, or lane produces a different digest.
            let messages: [Vec<u8>; 33] = core::array::from_fn(|lane| random(len, lane as u64));
            let refs = messages.each_ref().map(Vec::as_slice);
            for count in [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33] {
                let refs = &refs[..count];
                let expected: Vec<Digest> =
                    refs.iter().map(|message| reference(&[message])).collect();
                assert_eq!(Blake3::hash_many(refs), expected, "len={len} count={count}");
            }
        }

        // A length change splits the run.
        let messages: [Vec<u8>; 16] = core::array::from_fn(|lane| vec![lane as u8; 64]);
        let mut refs = messages.each_ref().map(Vec::as_slice);
        refs[9] = &messages[9][..63];
        let expected: Vec<Digest> = refs.iter().map(|message| reference(&[message])).collect();
        assert_eq!(Blake3::hash_many(&refs), expected);
    }

    #[test]
    fn test_hash_many_aliased_unaligned_inputs_match_individual_hashes() {
        let backing = random(2100, 0);
        for len in [129, 1025, 2049] {
            let messages: [&[u8]; 16] = core::array::from_fn(|lane| &backing[lane..lane + len]);
            let expected: Vec<Digest> = messages
                .iter()
                .map(|message| reference(&[message]))
                .collect();
            for count in 1..=messages.len() {
                assert_eq!(Blake3::hash_many(&messages[..count]), expected[..count]);
            }
            let repeated = [&backing[1..=len]; 16];
            assert_eq!(Blake3::hash_many(&repeated), vec![expected[1]; 16]);
        }
    }

    #[test]
    fn test_hash_with_matches_hash() {
        let data = random((1 << 20) + 5, 0);
        let rayon =
            commonware_parallel::Rayon::new(core::num::NonZeroUsize::new(4).unwrap()).unwrap();
        for len in [
            0,
            1,
            1024,
            TASK_LEN,
            TASK_LEN + 1,
            2 * TASK_LEN,
            2 * TASK_LEN + 1,
            3 * TASK_LEN + 17,
            8 * TASK_LEN,
            (1 << 20) + 5,
        ] {
            let message = &data[..len];
            let expected = reference(&[message]);
            let (a, b) = (len / 3, len / 3 + TASK_LEN.min(len - len / 3));
            let splits: [&[&[u8]]; 3] = [
                &[message],
                &[&message[..a], &message[a..b], &message[b..]],
                &[&[], message, &[]],
            ];
            // Many unaligned parts, so part boundaries fall inside chunks and tasks.
            let pages: Vec<&[u8]> = message.chunks(1000).collect();
            assert_eq!(
                Blake3::hash_with(&rayon, &pages),
                expected,
                "len={len} pages"
            );
            for parts in splits {
                assert_eq!(
                    Blake3::hash_with(&commonware_parallel::Sequential, parts),
                    expected,
                    "len={len}"
                );
                assert_eq!(Blake3::hash_with(&rayon, parts), expected, "len={len}");
            }
        }
    }

    #[test]
    fn test_hash_many_parts_matches_hash() {
        let data = random(4096, 0);
        for count in [0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 33] {
            let nodes: Vec<[&[u8]; 3]> = (0..count)
                .map(|i| [&data[i..i + 8], &data[i + 8..i + 40], &data[i + 40..i + 72]])
                .collect();
            let pairs: Vec<[&[u8]; 2]> = (0..count)
                .map(|i| [&data[i..i + 32], &data[i + 32..i + 64]])
                .collect();
            let mixed: Vec<[&[u8]; 2]> = (0..count)
                .map(|i| [&data[..i], &data[i..2 * i + 1000]])
                .collect();
            let check = |digests: Vec<Digest>, expected: Vec<Digest>| {
                assert_eq!(digests, expected, "count={count}");
            };
            check(
                Blake3::hash_many_parts(&nodes),
                nodes.iter().map(|parts| reference(parts)).collect(),
            );
            check(
                Blake3::hash_many_parts(&pairs),
                pairs.iter().map(|parts| reference(parts)).collect(),
            );
            check(
                Blake3::hash_many_parts(&mixed),
                mixed.iter().map(|parts| reference(parts)).collect(),
            );
        }
    }

    #[test]
    fn test_gather() {
        assert_eq!(gather(&[]), Some(([0; PAIR_LEN], 0)));
        let (buffer, len) = gather(&[&[1, 2], &[], &[3]]).unwrap();
        assert_eq!(len, 3);
        assert_eq!(buffer[..4], [1, 2, 3, 0]);
        assert!(gather(&[&[0; PAIR_LEN]]).is_some());
        assert!(gather(&[&[0; PAIR_LEN], &[0]]).is_none());
    }

    #[test]
    fn test_blake3_len() {
        assert_eq!(Digest::SIZE, DIGEST_LENGTH);
    }

    #[test]
    fn test_codec() {
        let msg = b"hello world";
        let mut hasher = Blake3::default();
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
