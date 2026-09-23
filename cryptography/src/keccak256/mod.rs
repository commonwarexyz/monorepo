//! Keccak-256 implementation of the [Hasher] trait.
//!
//! Uses the `sha3` crate with Keccak padding, as used by Ethereum.
//! Keccak-256 and SHA3-256 produce different digests.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Hasher, Keccak256};
//!
//! // Hash data in a single shot
//! let digest = Keccak256::hash(&[b"hello,", b"world!"]);
//! println!("digest: {:?}", digest);
//!
//! // Or stream data incrementally
//! let mut hasher = Keccak256::default();
//! hasher.update(b"hello,");
//! hasher.update(b"world!");
//! let (_hasher, digest) = hasher.finalize();
//! println!("digest: {:?}", digest);
//! ```

use crate::Hasher;
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_utils::{Array, Span};
use core::{
    fmt::{Debug, Display},
    ops::Deref,
};
use rand_core::CryptoRng;
use sha3::Digest as _;
use zeroize::Zeroize;

/// The underlying Keccak-256 implementation.
pub type CoreKeccak256 = sha3::Keccak256;

const DIGEST_LENGTH: usize = 32;

/// Keccak-256 hasher.
#[derive(Debug, Default)]
pub struct Keccak256 {
    hasher: CoreKeccak256,
}

impl Hasher for Keccak256 {
    type Digest = Digest;

    fn hash(parts: &[&[u8]]) -> Self::Digest {
        let mut hasher = Self::default();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().1
    }

    fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
        (Self::hash(left), Self::hash(right))
    }

    fn update(&mut self, message: &[u8]) -> &mut Self {
        self.hasher.update(message);
        self
    }

    fn finalize(mut self) -> (Self, Self::Digest) {
        let finalized = self.hasher.finalize_reset();
        let array: [u8; DIGEST_LENGTH] = finalized.into();
        (self, Self::Digest::from(array))
    }
}

/// Digest of a Keccak-256 hashing operation.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, FixedArray)]
#[fixed_array(infallible)]
#[repr(transparent)]
pub struct Digest(pub [u8; DIGEST_LENGTH]);

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Digest {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0..=256)?;
        let data = u.bytes(len)?;
        Ok(Keccak256::hash(&[data]))
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

    const EMPTY_DIGEST: [u8; DIGEST_LENGTH] =
        hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    const ABC_DIGEST: [u8; DIGEST_LENGTH] =
        hex!("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

    #[test]
    fn test_known_answers_and_reset() {
        assert_eq!(Keccak256::hash(&[]).as_ref(), EMPTY_DIGEST);
        assert_eq!(Keccak256::hash(&[b"abc"]).as_ref(), ABC_DIGEST);
        assert_eq!(Keccak256::hash(&[b"a", b"", b"bc"]).as_ref(), ABC_DIGEST);
        assert_eq!(
            Keccak256::hash_pair(&[], &[b"a", b"bc"]),
            (Digest(EMPTY_DIGEST), Digest(ABC_DIGEST))
        );

        let mut hasher = Keccak256::default();
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

    #[test]
    fn test_rate_boundaries() {
        for len in [0, 1, 135, 136, 137, 271, 272, 273, 1024] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected: [u8; DIGEST_LENGTH] = CoreKeccak256::digest(&data).into();
            for split in 0..=len {
                let parts = [&data[..split], &[][..], &data[split..]];
                assert_eq!(Keccak256::hash(&parts).as_ref(), expected);
                crate::fuzz::Plan::<Keccak256>::new(
                    parts.iter().map(|p| p.to_vec()).collect(),
                    vec![b"abc".to_vec()],
                )
                .run();
            }
        }
    }

    #[test]
    fn test_codec_and_zeroize() {
        let mut digest = Keccak256::hash(&[b"abc"]);
        let encoded = digest.encode();
        assert_eq!(Digest::SIZE, DIGEST_LENGTH);
        assert_eq!(encoded.as_ref(), ABC_DIGEST);
        assert_eq!(Digest::decode(encoded).unwrap(), digest);
        assert!(Digest::decode(Copying(&ABC_DIGEST[..31])).is_err());
        digest.zeroize();
        assert_eq!(digest, <Digest as crate::Digest>::EMPTY);
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
