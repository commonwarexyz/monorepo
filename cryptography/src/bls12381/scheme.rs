//! BLS12-381 implementation of the [crate::Verifier] and [crate::Signer] traits.
//!
//! This implementation uses the `blst` crate for BLS12-381 operations. This
//! crate implements serialization according to the "ZCash BLS12-381" specification
//! (<https://github.com/supranational/blst/tree/master?tab=readme-ov-file#serialization-format>)
//! and hashes messages according to RFC 9380.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{bls12381, PrivateKey, PublicKey, Signature, Verifier as _, Signer as _};
//! use commonware_math::algebra::Random;
//! use commonware_utils::test_rng;
//!
//! let mut rng = test_rng();
//!
//! // Generate a new private key
//! let mut signer = bls12381::PrivateKey::random(&mut rng);
//!
//! // Create a message to sign
//! let namespace = b"demo";
//! let msg = b"hello, world!";
//!
//! // Sign the message
//! let signature = signer.sign(namespace, msg);
//!
//! // Verify the signature
//! assert!(signer.public_key().verify(namespace, msg, &signature));
//! ```

use super::primitives::{
    group::{self, Private, Scalar, ScalarReadCfg},
    ops,
    variant::{MinPk, Variant},
};
use crate::{BatchVerifier, HardenError, Secret, Signer as _};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Decode, DecodeExt, EncodeFixed, Error as CodecError, FixedArray, FixedSize, Read, ReadExt,
    Write,
};
use commonware_formatting::Hex;
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_parallel::Strategy;
use commonware_utils::{Array, Span};
use core::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    ops::Deref,
};
use ctutils::{Choice, CtEq};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

const CURVE_NAME: &str = "bls12381";

/// A scalar and its cached canonical encoding.
///
/// Both fields remain immutable and occupy the same protected value after hardening.
#[derive(Clone)]
struct PrivateValue {
    raw: Zeroizing<[u8; group::PRIVATE_KEY_LENGTH]>,
    scalar: Scalar,
}

impl CtEq for PrivateValue {
    fn ct_eq(&self, other: &Self) -> Choice {
        // The immutable cache is determined by the scalar, whose comparison is constant-time.
        self.scalar.ct_eq(&other.scalar)
    }
}

/// BLS12-381 private key.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    key: Secret<PrivateValue>,
}

impl PrivateKey {
    /// Creates an inline key and caches its canonical encoding.
    fn new(scalar: Scalar) -> Self {
        Self {
            key: Secret::new(PrivateValue {
                raw: scalar.as_slice(),
                scalar,
            }),
        }
    }

    /// Moves the private scalar and its cached encoding into hardened storage.
    ///
    /// Clones then share the protected allocation. Already hardened keys are
    /// unchanged. Failure consumes the key. Earlier clones and exported material
    /// are unaffected.
    ///
    /// See [Secret::try_harden](crate::Secret::try_harden) for platform requirements,
    /// protection guarantees, and limits.
    pub fn try_harden(self) -> Result<Self, HardenError> {
        Ok(Self {
            key: self.key.try_harden()?,
        })
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // PrivateValue compares its scalar through Secret's constant-time equality.
        self.key == other.key
    }
}

impl Eq for PrivateKey {}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.access(|value| value.raw.write(buf));
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = Zeroizing::new(<[u8; Self::SIZE]>::read(buf)?);
        let scalar = Scalar::decode_cfg(raw.as_ref(), &ScalarReadCfg::RejectZero)
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        Ok(Self {
            key: Secret::new(PrivateValue { raw, scalar }),
        })
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = group::PRIVATE_KEY_LENGTH;
}

impl TryFrom<Private> for PrivateKey {
    type Error = HardenError;

    /// Converts a primitive private key, preserving whether its storage is hardened.
    ///
    /// Inline input produces an inline key without allocating. Hardened input
    /// requires a new protected allocation containing the scalar and its encoding.
    /// Existing clones retain their original storage and do not share the new allocation.
    /// The scalar passes through ordinary temporary storage during conversion.
    ///
    /// # Errors
    ///
    /// Returns [HardenError] if hardening the new allocation fails. The input is
    /// consumed on success or failure. See [Secret::try_harden] for protection limits.
    fn try_from(key: Private) -> Result<Self, Self::Error> {
        let hardened = key.is_hardened();
        let key = Self::new(key.extract_or_clone());
        if hardened { key.try_harden() } else { Ok(key) }
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl crate::PrivateKey for PrivateKey {}

impl crate::Signer for PrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn public_key(&self) -> Self::PublicKey {
        let public = self
            .key
            .access(|value| <MinPk as Variant>::Public::generator() * &value.scalar);
        public.into()
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        // Hash public input before opening the private allocation.
        let hashed = ops::hash_with_namespace::<MinPk>(MinPk::MESSAGE, namespace, msg);
        self.key.access(|value| hashed * &value.scalar).into()
    }
}

impl Random for PrivateKey {
    fn random(rng: impl CryptoRng) -> Self {
        Self::new(Scalar::random(rng))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PrivateKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use rand::{SeedableRng, rngs::StdRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        Ok(Self::random(&mut rand))
    }
}

impl crate::PublicKey for PublicKey {}

impl crate::Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        ops::verify_message::<MinPk>(&self.key, namespace, msg, &sig.signature).is_ok()
    }
}

/// BLS12-381 public key.
#[derive(Clone, Eq, PartialEq, FixedArray)]
pub struct PublicKey {
    raw: [u8; <MinPk as Variant>::Public::SIZE],
    key: <MinPk as Variant>::Public,
}

impl From<PrivateKey> for PublicKey {
    fn from(private_key: PrivateKey) -> Self {
        private_key.public_key()
    }
}

impl AsRef<<MinPk as Variant>::Public> for PublicKey {
    fn as_ref(&self) -> &<MinPk as Variant>::Public {
        &self.key
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let key = <MinPk as Variant>::Public::decode(raw.as_ref())
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        Ok(Self { raw, key })
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = <MinPk as Variant>::Public::SIZE;
}

impl Span for PublicKey {}

impl Array for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for PublicKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<<MinPk as Variant>::Public> for PublicKey {
    fn from(key: <MinPk as Variant>::Public) -> Self {
        let raw = key.encode_fixed();
        Self { raw, key }
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKey::random(&mut rand);
        Ok(private_key.public_key())
    }
}

/// BLS12-381 signature.
#[derive(Clone, Eq, PartialEq, FixedArray)]
pub struct Signature {
    raw: [u8; <MinPk as Variant>::Signature::SIZE],
    signature: <MinPk as Variant>::Signature,
}

impl crate::Signature for Signature {}

impl AsRef<<MinPk as Variant>::Signature> for Signature {
    fn as_ref(&self) -> &<MinPk as Variant>::Signature {
        &self.signature
    }
}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        let signature = <MinPk as Variant>::Signature::decode(raw.as_ref())
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        Ok(Self { raw, signature })
    }
}

impl FixedSize for Signature {
    const SIZE: usize = <MinPk as Variant>::Signature::SIZE;
}

impl Span for Signature {}

impl Array for Signature {}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl Deref for Signature {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl From<<MinPk as Variant>::Signature> for Signature {
    fn from(signature: <MinPk as Variant>::Signature) -> Self {
        let raw = signature.encode_fixed();
        Self { raw, signature }
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKey::random(&mut rand);
        let len = u.arbitrary::<usize>()? % 256;
        let message = u
            .arbitrary_iter()?
            .take(len)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(private_key.sign(b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_TEST", &message))
    }
}

/// BLS12-381 batch verifier.
pub struct Batch {
    publics: Vec<<MinPk as Variant>::Public>,
    hms: Vec<<MinPk as Variant>::Signature>,
    signatures: Vec<<MinPk as Variant>::Signature>,
}

impl BatchVerifier for Batch {
    type PublicKey = PublicKey;

    fn new(capacity: usize) -> Self {
        Self {
            publics: Vec::with_capacity(capacity),
            hms: Vec::with_capacity(capacity),
            signatures: Vec::with_capacity(capacity),
        }
    }

    fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        self.publics.push(public_key.key);
        let hm = ops::hash_with_namespace::<MinPk>(MinPk::MESSAGE, namespace, message);
        self.hms.push(hm);
        self.signatures.push(signature.signature);
        true
    }

    fn verify<R: CryptoRng>(self, rng: &mut R, strategy: &impl Strategy) -> bool {
        MinPk::batch_verify(rng, &self.publics, &self.hms, &self.signatures, strategy).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Verifier as _, bls12381};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    #[test]
    fn test_codec_private_key() {
        let original =
            parse_private_key("0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3")
                .unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), bls12381::PrivateKey::SIZE);
        let decoded = bls12381::PrivateKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_public_key() {
        let original =
            parse_public_key("0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a")
            .unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), PublicKey::SIZE);
        let decoded = PublicKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_signature() {
        let original =
            parse_signature("0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb")
            .unwrap();
        let encoded = original.encode();
        assert_eq!(encoded.len(), Signature::SIZE);
        let decoded = Signature::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    fn parse_private_key(private_key: &str) -> Result<PrivateKey, CodecError> {
        PrivateKey::decode(
            commonware_formatting::from_hex(private_key)
                .unwrap()
                .as_ref(),
        )
    }

    fn parse_public_key(public_key: &str) -> Result<PublicKey, CodecError> {
        PublicKey::decode(
            commonware_formatting::from_hex(public_key)
                .unwrap()
                .as_ref(),
        )
    }

    fn parse_signature(signature: &str) -> Result<Signature, CodecError> {
        Signature::decode(commonware_formatting::from_hex(signature).unwrap().as_ref())
    }

    #[test]
    fn test_from_private() {
        let mut rng = test_rng();
        let private = Private::random(&mut rng);
        let private_key = PrivateKey::try_from(private).unwrap();
        let msg = b"test message";
        let sig = private_key.sign(b"ns", msg);
        assert!(private_key.public_key().verify(b"ns", msg, &sig));
    }

    #[test]
    fn test_private_key_redacted() {
        let mut rng = test_rng();
        let private_key = PrivateKey::random(&mut rng);
        let debug = format!("{:?}", private_key);
        let display = format!("{}", private_key);
        assert!(debug.contains("REDACTED"));
        assert!(display.contains("REDACTED"));
    }

    #[test]
    fn batch_verify_empty() {
        let batch = Batch::new(0);
        assert!(!batch.verify(&mut test_rng(), &Sequential));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PublicKey>,
            CodecConformance<PrivateKey>,
            CodecConformance<Signature>,
        }
    }
}
