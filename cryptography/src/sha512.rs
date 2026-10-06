//! SHA-512 implementation of the [Hasher] trait.
//!
//! This implementation uses the `sha2` crate to generate SHA-512 digests. On x86-64 CPUs with
//! AVX-512F, [Hasher::hash_many] hashes up to eight messages at once, one per SIMD lane. On
//! aarch64 CPUs with the SHA-512 instructions, it hashes messages in pairs, interleaving their
//! rounds.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Hasher, Sha512};
//!
//! // Hash data in a single shot
//! let digest = Sha512::hash(&[b"hello,", b"world!"]);
//! println!("digest: {:?}", digest);
//!
//! // Or stream data incrementally
//! let mut hasher = Sha512::default();
//! hasher.update(b"hello,");
//! hasher.update(b"world!");
//! let (_hasher, digest) = hasher.finalize();
//! println!("digest: {:?}", digest);
//!
//! // Hash independent messages, which may differ in length, in one call
//! let messages: [&[u8]; 3] = [b"a", b"bc", b"def"];
//! let digests = Sha512::hash_many(&messages);
//! assert_eq!(digests[1], Sha512::hash(&[b"bc"]));
//! ```

use crate::Hasher;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_utils::{Array, Span, sequence::FixedBytes};
use core::{
    cmp::Ordering,
    fmt::{Debug, Display},
    ops::Deref,
};
use rand_core::CryptoRng;
use sha2::Digest as _;
use zeroize::Zeroize;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod avx512;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod padding;

/// The underlying SHA-512 implementation.
pub type CoreSha512 = sha2::Sha512;

/// Length of a SHA-512 digest in bytes.
const DIGEST_LENGTH: usize = 64;

#[cfg(target_arch = "x86_64")]
cpufeatures::new!(has_avx512f, "avx512f");
// Rust and cpufeatures group the Armv8.2 SHA-512 instructions with SHA-3's under `sha3`.
#[cfg(target_arch = "aarch64")]
cpufeatures::new!(has_sha3, "sha3");

/// SHA-512 hasher.
#[derive(Debug, Default)]
pub struct Sha512 {
    hasher: CoreSha512,
}

impl Hasher for Sha512 {
    type Digest = Digest;

    fn hash(parts: &[&[u8]]) -> Self::Digest {
        let mut hasher = CoreSha512::new();
        for part in parts {
            hasher.update(part);
        }
        Digest(hasher.finalize().into())
    }

    fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
        (Self::hash(left), Self::hash(right))
    }

    fn hash_many<M: AsRef<[u8]>>(messages: &[M]) -> Vec<Self::Digest> {
        // With AVX-512F, hash up to eight messages per kernel call, one per lane.
        #[cfg(target_arch = "x86_64")]
        if has_avx512f::get() {
            let mut digests = Vec::with_capacity(messages.len());
            for chunk in messages.chunks(avx512::LANES) {
                let mut lanes: [&[u8]; avx512::LANES] = [&[]; avx512::LANES];
                for (lane, message) in lanes.iter_mut().zip(chunk) {
                    *lane = message.as_ref();
                }

                // A short final chunk passes only its own messages, and the zero digests of the
                // unused lanes are dropped.
                // SAFETY: AVX-512F support was just detected.
                let chunk_digests = unsafe { avx512::hash(&lanes[..chunk.len()]) };
                digests.extend_from_slice(&chunk_digests[..chunk.len()]);
            }
            return digests;
        }

        // With the SHA-512 instructions, hash the messages in interleaved pairs.
        #[cfg(target_arch = "aarch64")]
        if has_sha3::get() {
            let mut digests = Vec::with_capacity(messages.len());
            let (pairs, remainder) = messages.as_chunks::<{ aarch64::LANES }>();
            for pair in pairs {
                let lanes = [pair[0].as_ref(), pair[1].as_ref()];

                // SAFETY: Support for the SHA-512 instructions was just detected.
                digests.extend_from_slice(&unsafe { aarch64::hash(&lanes) });
            }

            // An odd last message has no partner to interleave with, so it is hashed alone.
            for message in remainder {
                digests.push(Self::hash(&[message.as_ref()]));
            }
            return digests;
        }

        // Without a multi-message kernel, hash each message alone.
        messages
            .iter()
            .map(|message| Self::hash(&[message.as_ref()]))
            .collect()
    }

    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.hasher.update(message);
        self
    }

    fn finalize(mut self) -> (Self, Self::Digest) {
        let finalized = self.hasher.finalize_reset();
        (self, Digest(finalized.into()))
    }
}

/// Digest of a SHA-512 hashing operation.
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
        let len = u.int_in_range(0..=256)?;
        let data = u.bytes(len)?;
        Ok(Sha512::hash(&[data]))
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
    use commonware_formatting::hex;

    const EMPTY_DIGEST: [u8; DIGEST_LENGTH] = hex!(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
    const ABC_DIGEST: [u8; DIGEST_LENGTH] = hex!(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );

    /// The `sha2` digest of `message`.
    fn expected(message: &[u8]) -> Digest {
        Digest(CoreSha512::digest(message).into())
    }

    /// A `len`-byte message whose bytes depend on `seed`.
    fn message(len: usize, seed: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(31) ^ seed.wrapping_mul(0x9e37)) as u8)
            .collect()
    }

    /// Checks [Sha512::hash_many] against `sha2` one message at a time.
    fn check_hash_many(messages: &[Vec<u8>]) {
        let digests: Vec<Digest> = messages.iter().map(|message| expected(message)).collect();
        assert_eq!(Sha512::hash_many(messages), digests);
    }

    #[test]
    fn test_known_answers_and_reset() {
        // Every one-shot entry point gives the known digests of the empty message and `abc`,
        // including when a message is split into parts around an empty one.
        assert_eq!(Sha512::hash(&[]).as_ref(), EMPTY_DIGEST);
        assert_eq!(Sha512::hash(&[b"abc"]).as_ref(), ABC_DIGEST);
        assert_eq!(Sha512::hash(&[b"a", b"", b"bc"]).as_ref(), ABC_DIGEST);
        assert_eq!(
            Sha512::hash_pair(&[], &[b"a", b"bc"]),
            (Digest(EMPTY_DIGEST), Digest(ABC_DIGEST))
        );
        assert_eq!(
            Sha512::hash_many(&[b"".as_slice(), b"abc"]),
            [Digest(EMPTY_DIGEST), Digest(ABC_DIGEST)]
        );

        // Stream each message a byte at a time and keep the hasher that `finalize` returns. Every
        // digest after the first matches only if finalizing reset the hasher.
        let mut hasher = Sha512::default();
        for message in [b"abc".as_slice(), b"", b"abc", b""] {
            for byte in message {
                hasher.update(core::slice::from_ref(byte));
            }
            let (reset, digest) = hasher.finalize();
            let expected = if message.is_empty() {
                EMPTY_DIGEST
            } else {
                ABC_DIGEST
            };
            assert_eq!(digest.as_ref(), expected);
            hasher = reset;
        }
    }

    /// Every message count up to 20 (two full lane groups and a partial one) at every length
    /// in `0..=300`.
    #[test]
    fn test_hash_many_equal_lengths() {
        for len in 0..=300 {
            let messages: Vec<Vec<u8>> = (0..20).map(|lane| message(len, lane)).collect();
            for count in 0..=messages.len() {
                check_hash_many(&messages[..count]);
            }
        }
    }

    /// Every message count up to 20 with lengths that differ within each lane group, where one
    /// message of each length in `0..=300` (and two longer lengths) moves across lanes, so
    /// messages both run out early and outlast the rest of their group.
    #[test]
    fn test_hash_many_mixed_lengths() {
        for len in (0..=300).chain([1000, 4113]) {
            for count in 1..=20 {
                let messages: Vec<Vec<u8>> = (0..count)
                    .map(|lane| {
                        // Message `len % count` has length `len`, and the others take lengths
                        // spread over `0..=300`.
                        let other = (len * 7 + lane * 37) % 301;
                        message(if lane == len % count { len } else { other }, lane)
                    })
                    .collect();
                check_hash_many(&messages);
            }
        }
    }

    /// Overlapping and aliased messages borrowed from one buffer.
    #[test]
    fn test_hash_many_overlapping_messages() {
        // Message `lane` starts at byte `lane` and spans `100 + 12 * lane` bytes, so the
        // messages overlap and differ in length.
        let backing = message(400, 0);
        let messages: Vec<&[u8]> = (0..20)
            .map(|lane| &backing[lane..lane * 13 + 100])
            .collect();
        let digests: Vec<Digest> = messages.iter().map(|message| expected(message)).collect();
        assert_eq!(Sha512::hash_many(&messages), digests);

        // Nine aliases of one buffer fill a group of eight lanes and spill into the next. For the
        // paired kernel, they leave an odd message out.
        assert_eq!(
            Sha512::hash_many(&[&backing[..]; 9]),
            [expected(&backing); 9]
        );
    }

    /// The AVX-512 kernel runs on every CPU that has AVX-512F, so the tests above cover it
    /// there.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_avx512_detection() {
        assert_eq!(
            has_avx512f::get(),
            std::arch::is_x86_feature_detected!("avx512f")
        );
    }

    /// The paired kernel runs on every CPU that has the SHA-512 instructions, so the tests above
    /// cover it there.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_sha3_detection() {
        assert_eq!(
            has_sha3::get(),
            std::arch::is_aarch64_feature_detected!("sha3")
        );
    }

    #[test]
    fn test_codec_and_zeroize() {
        // A digest round-trips as its raw bytes, and a truncated encoding fails to decode.
        let mut digest = Sha512::hash(&[b"abc"]);
        let encoded = digest.encode();
        assert_eq!(Digest::SIZE, DIGEST_LENGTH);
        assert_eq!(encoded.as_ref(), ABC_DIGEST);
        assert_eq!(Digest::decode(encoded).unwrap(), digest);
        assert!(Digest::decode(Copying(&ABC_DIGEST[..DIGEST_LENGTH - 1])).is_err());

        // Zeroizing leaves the all-zero `EMPTY` digest.
        digest.zeroize();
        assert_eq!(digest, <Digest as crate::Digest>::EMPTY);
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
