//! BLAKE3 implementation of the [Hasher] trait.
//!
//! This implementation uses the [blake3] crate to generate BLAKE3 digests. [Hasher::hash_with]
//! splits a message of at least 128 KiB along the BLAKE3 tree and hashes the subtrees across the
//! given strategy.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Hasher, blake3::Blake3};
//! use commonware_parallel::Rayon;
//! use std::num::NonZeroUsize;
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
//! // Hash a long message across a thread pool
//! let strategy = Rayon::new(NonZeroUsize::new(4).unwrap()).unwrap();
//! let message = vec![7u8; 1 << 20];
//! assert_eq!(
//!     Blake3::hash_with(&[&message], &strategy),
//!     Blake3::hash(&[&message]),
//! );
//! ```

use crate::Hasher;
use blake3::{
    CHUNK_LEN, Hash,
    hazmat::{ChainingValue, HasherExt as _, Mode, merge_subtrees_non_root, merge_subtrees_root},
};
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_utils::{Array, Span, sequence::FixedBytes};
use core::{
    cmp::Ordering,
    fmt::{Debug, Display},
    ops::Deref,
};
use rand_core::CryptoRng;
use zeroize::Zeroize;

/// Re-export [blake3::Hasher] as `CoreBlake3` for external use if needed.
pub type CoreBlake3 = blake3::Hasher;

const DIGEST_LENGTH: usize = blake3::OUT_LEN;

/// Divisor of a message's length that bounds each subtree [`Hasher::hash_with`] hashes as one
/// task, so that a split message spreads across at least this many tasks.
const SUBTREES: usize = 8;

/// Lower clamp, in bytes, on the subtree bound: 16 chunks, the widest batch the SIMD kernels
/// compress at once.
pub(crate) const MIN_SUBTREE_LEN: usize = 16 * CHUNK_LEN;

/// Upper clamp, in bytes, on the subtree bound: 64 chunks, enough to amortize the cost of a fork.
const MAX_SUBTREE_LEN: usize = 64 * CHUNK_LEN;

/// Length, in bytes, of the shortest message [`Hasher::hash_with`] splits: [`SUBTREES`] subtrees of
/// [`MIN_SUBTREE_LEN`] bytes.
pub(crate) const MIN_SPLIT_LEN: usize = SUBTREES * MIN_SUBTREE_LEN;

/// Hash the concatenation of `parts` on the calling thread.
fn hash_serial(parts: &[&[u8]]) -> Digest {
    let mut hasher = CoreBlake3::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Hash the `len`-byte concatenation of `parts`, which spans more than one chunk, across `strategy`
/// as subtrees of at most `len / SUBTREES` bytes, clamped to [`MIN_SUBTREE_LEN`] and
/// [`MAX_SUBTREE_LEN`].
fn hash_subtrees(parts: &[&[u8]], len: usize, strategy: &impl Strategy) -> Digest {
    let root = Node {
        parts,
        skip: 0,
        offset: 0,
        len,
        task_len: (len / SUBTREES).clamp(MIN_SUBTREE_LEN, MAX_SUBTREE_LEN),
    };
    let (left, right) = root.children(strategy);
    merge_subtrees_root(&left, &right, Mode::Hash).into()
}

/// A node of a message's BLAKE3 tree: the `len` bytes at byte `offset` of the message, which
/// start `skip` bytes into the first of `parts`. Subtrees of at most `task_len` bytes hash as one
/// task.
///
/// `parts` holds every byte of the node, and `skip` is at most the length of its first part.
#[derive(Clone, Copy)]
struct Node<'a> {
    parts: &'a [&'a [u8]],
    skip: usize,
    offset: usize,
    len: usize,
    task_len: usize,
}

impl Node<'_> {
    /// Hash the chaining values of the children of a node that spans more than one chunk, in
    /// parallel across `strategy`.
    fn children(self, strategy: &impl Strategy) -> (ChainingValue, ChainingValue) {
        // The left child is the largest power-of-two number of chunks that leaves the right
        // child nonempty, which for a node of more than one chunk is the largest power of two
        // below its length. The right child starts in the first part that extends past it.
        let left_len = 1 << (self.len - 1).ilog2();
        let mut skip = self.skip + left_len;
        let mut index = 0;
        while skip >= self.parts[index].len() {
            skip -= self.parts[index].len();
            index += 1;
        }
        let left = Node {
            parts: &self.parts[..=index],
            len: left_len,
            ..self
        };
        let right = Node {
            parts: &self.parts[index..],
            skip,
            offset: self.offset + left_len,
            len: self.len - left_len,
            task_len: self.task_len,
        };
        strategy.join(
            || left.chaining_value(strategy),
            || right.chaining_value(strategy),
        )
    }

    /// Hash the node's chaining value, splitting it until every subtree fits in `task_len` bytes.
    fn chaining_value(self, strategy: &impl Strategy) -> ChainingValue {
        if self.len > self.task_len {
            let (left, right) = self.children(strategy);
            return merge_subtrees_non_root(&left, &right, Mode::Hash);
        }

        // Feed the node's bytes, which start `skip` bytes into the first part.
        let mut hasher = CoreBlake3::new();
        hasher.set_input_offset(self.offset as u64);
        let mut skip = self.skip;
        let mut remaining = self.len;
        for part in self.parts {
            let bytes = &part[skip..];
            let take = bytes.len().min(remaining);
            hasher.update(&bytes[..take]);
            remaining -= take;
            if remaining == 0 {
                break;
            }
            skip = 0;
        }
        hasher.finalize_non_root()
    }
}

/// BLAKE3 hasher.
#[derive(Debug, Default)]
pub struct Blake3 {
    hasher: CoreBlake3,
}

impl Hasher for Blake3 {
    type Digest = Digest;

    fn hash_with(parts: &[&[u8]], strategy: &impl Strategy) -> Self::Digest {
        // A message shorter than `MIN_SPLIT_LEN` hashes on the calling thread. A total that
        // overflows `usize` (possible only when parts alias) hashes serially, since the streaming
        // hasher counts bytes in a `u64`.
        match parts
            .iter()
            .try_fold(0usize, |len, part| len.checked_add(part.len()))
        {
            Some(len) if len >= MIN_SPLIT_LEN => strategy.run(
                len,
                || hash_serial(parts),
                || hash_subtrees(parts, len, strategy),
            ),
            _ => hash_serial(parts),
        }
    }

    fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
        (Self::hash(left), Self::hash(right))
    }

    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.hasher.update(message);
        self
    }

    fn finalize(mut self) -> (Self, Self::Digest) {
        let finalized = self.hasher.finalize();
        self.hasher.reset();
        let array: [u8; DIGEST_LENGTH] = finalized.into();
        (self, Self::Digest::from(array))
    }
}

/// Digest of a BLAKE3 hashing operation.
#[derive(Clone, Copy, Eq, PartialEq, Hash, FixedArray)]
#[fixed_array(infallible)]
#[repr(transparent)]
pub struct Digest(pub [u8; DIGEST_LENGTH]);

impl Ord for Digest {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        FixedBytes::new(self.0).cmp(&FixedBytes::new(other.0))
    }
}

impl PartialOrd for Digest {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

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
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{NZUsize, TestRng};
    use rand::Rng as _;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering::Relaxed},
        mpsc,
    };

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

    /// Official BLAKE3 test vectors. Hashing 16 KiB or more in one update reaches the 16-way
    /// AVX-512 chunk kernel, and 32 KiB or more also reaches the 16-way parent kernel. Each vector
    /// also hashes as subtrees across workers.
    #[test]
    fn test_official_vectors() {
        let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
        const VECTORS: [(usize, [u8; DIGEST_LENGTH]); 3] = [
            (
                16384,
                commonware_formatting::hex!(
                    "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"
                ),
            ),
            (
                31744,
                commonware_formatting::hex!(
                    "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"
                ),
            ),
            (
                102400,
                commonware_formatting::hex!(
                    "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"
                ),
            ),
        ];
        for (len, expected) in VECTORS {
            // The official input repeats the bytes 0 through 250.
            let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut hasher = Blake3::default();
            hasher.update(&input);
            let (_, digest) = hasher.finalize();
            assert_eq!(digest.as_ref(), expected, "len {len}");
            let digest = Blake3::hash_with(&[&input], &strategy);
            assert_eq!(digest.as_ref(), expected, "len {len}");
            let digest = hash_subtrees(&[&input], len, &strategy);
            assert_eq!(digest.as_ref(), expected, "len {len}");
        }
    }

    /// Messages around multiples of [`MIN_SUBTREE_LEN`] and around [`MIN_SPLIT_LEN`], given whole,
    /// cut inside chunks and subtrees, padded with empty parts, and paged, hash to the reference
    /// digest on the calling thread and across workers. Splitting into subtrees on the calling
    /// thread also matches, down to two chunks.
    #[test]
    fn test_hash_long_messages() {
        let strategy = Rayon::new(NZUsize!(4)).unwrap().manual();
        let data = random((1 << 20) + 5000, 0);
        for len in [
            0,
            1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN + 7,
            MIN_SUBTREE_LEN - 1,
            MIN_SUBTREE_LEN,
            MIN_SUBTREE_LEN + 1,
            MIN_SUBTREE_LEN + CHUNK_LEN,
            2 * MIN_SUBTREE_LEN - 1,
            2 * MIN_SUBTREE_LEN,
            2 * MIN_SUBTREE_LEN + 1,
            2 * MIN_SUBTREE_LEN + 3 * CHUNK_LEN + 7,
            3 * MIN_SUBTREE_LEN + 17,
            MIN_SPLIT_LEN - 1,
            MIN_SPLIT_LEN,
            MIN_SPLIT_LEN + MIN_SUBTREE_LEN + 1,
            3 * MIN_SPLIT_LEN + 17,
            (1 << 20) + 5000,
        ] {
            let message = &data[..len];
            let expected: Digest = blake3::hash(message).into();
            let (a, b) = (len / 3, len / 3 + MIN_SUBTREE_LEN.min(len - len / 3));
            let splits: [Vec<&[u8]>; 4] = [
                vec![message],
                vec![&message[..a], &message[a..b], &message[b..]],
                vec![&[], message, &[]],
                message.chunks(1000).collect(),
            ];
            for parts in &splits {
                assert_eq!(Blake3::hash(parts), expected, "len={len}");
                assert_eq!(Blake3::hash_with(parts, &strategy), expected, "len={len}");
                if len > CHUNK_LEN {
                    assert_eq!(
                        hash_subtrees(parts, len, &Sequential),
                        expected,
                        "len={len}"
                    );
                }
            }
        }
    }

    /// A message of at least [`MIN_SPLIT_LEN`] bytes is hashed across the strategy's pool, and a
    /// shorter one on the calling thread.
    #[test]
    fn test_hash_splits_long_messages() {
        // One worker, planned as four, counts the jobs it runs while looping. Splitting a message
        // from outside the pool hands it one job, whose nested forks stay on the worker.
        let pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .unwrap(),
        );
        let strategy = Rayon::with_pool(pool.clone())
            .with_parallelism(NZUsize!(4))
            .manual();
        let data = random(2 * MIN_SPLIT_LEN, 0);
        for (len, jobs) in [
            (MIN_SPLIT_LEN - 1, 0),
            (MIN_SPLIT_LEN, 1),
            (2 * MIN_SPLIT_LEN, 1),
        ] {
            let done = Arc::new(AtomicBool::new(false));
            let (started, ready) = mpsc::channel();
            let (sender, receiver) = mpsc::channel();
            pool.spawn({
                let done = done.clone();
                move || {
                    started.send(()).unwrap();
                    let mut jobs = 0;
                    while !done.load(Relaxed) {
                        if rayon::yield_now() == Some(rayon::Yield::Executed) {
                            jobs += 1;
                        }
                    }
                    sender.send(jobs).unwrap();
                }
            });
            ready.recv().unwrap();

            // Hash, then release the worker and compare its job count.
            let message = &data[..len];
            let digest = Blake3::hash_with(&[message], &strategy);
            done.store(true, Relaxed);
            assert_eq!(digest, blake3::hash(message).into(), "len={len}");
            assert_eq!(receiver.recv().unwrap(), jobs, "len={len}");
        }
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

    #[test]
    fn test_digest_ord() {
        let a = Digest([0; DIGEST_LENGTH]);
        let mut b = a;
        b.0[DIGEST_LENGTH - 1] = 1;

        // The first byte decides even when the remaining bytes order the other way.
        let mut c = a;
        c.0[0] = 0x7f;
        c.0[1..].fill(0xff);
        let mut d = a;
        d.0[0] = 0x80;
        for (a, b, expected) in [
            (a, a, Ordering::Equal),
            (a, b, Ordering::Less),
            (b, a, Ordering::Greater),
            (c, d, Ordering::Less),
            (d, c, Ordering::Greater),
        ] {
            assert_eq!(a.cmp(&b), expected);
            assert_eq!(a.partial_cmp(&b), Some(expected));
        }
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
