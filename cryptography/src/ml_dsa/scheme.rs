use crate::Secret;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(all(not(feature = "std"), feature = "arbitrary"))]
use alloc::vec::Vec;
use bytes::{BufMut, Bytes};
use commonware_codec::{
    Buf, Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write, util::at_least,
};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_utils::{Array, Span, union_unique};
use core::{
    cmp::Ordering,
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
use ctutils::CtEq as _;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair as _, MlDsa65, Seed, Signer as _, SigningKey,
    VerifyingKey,
};
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use std::sync::Arc;
use zeroize::Zeroizing;

const NAME: &str = "ml_dsa";
const PRIVATE_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 1952;
const SIGNATURE_LENGTH: usize = 3309;

const _: () = {
    assert!(size_of::<Seed>() == PRIVATE_KEY_LENGTH);
    assert!(size_of::<EncodedVerifyingKey<MlDsa65>>() == PUBLIC_KEY_LENGTH);
    assert!(size_of::<EncodedSignature<MlDsa65>>() == SIGNATURE_LENGTH);
};

/// ML-DSA-65 Private Key.
///
/// The key is identified by its 32-byte seed. The expanded signing key and the derived
/// [PublicKey] are computed once when the key is created or decoded and are shared between
/// clones.
#[derive(Clone)]
pub struct PrivateKey {
    // The signing key zeroizes its seed and expanded key (including heap-allocated parts) on drop.
    key: Arc<Secret<SigningKey<MlDsa65>>>,
    public_key: PublicKey,
}

impl PrivateKey {
    /// Derives the key pair from a seed (FIPS 204 `ML-DSA.KeyGen_internal`).
    fn expand(seed: &Seed) -> Self {
        let key = SigningKey::<MlDsa65>::from_seed(seed);
        let public_key = PublicKey::new(key.verifying_key());
        Self {
            key: Arc::new(Secret::new(key)),
            public_key,
        }
    }
}

impl crate::PrivateKey for PrivateKey {}

impl crate::Signer for PrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        let payload = union_unique(namespace, msg);
        let signature = self
            .key
            .expose(|key| key.try_sign(&payload))
            .expect("signing with an empty context cannot fail");
        Signature {
            raw: Bytes::copy_from_slice(&signature.encode()),
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }
}

impl Random for PrivateKey {
    fn random(mut rng: impl CryptoRng) -> Self {
        let mut seed = Zeroizing::new(Seed::default());
        rng.fill_bytes(seed.as_mut_slice());
        Self::expand(&seed)
    }
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.expose(|key| buf.put_slice(key.as_seed()));
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, PRIVATE_KEY_LENGTH)?;
        let mut seed = Zeroizing::new(Seed::default());
        buf.copy_to_slice(seed.as_mut_slice());
        Ok(Self::expand(&seed))
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = PRIVATE_KEY_LENGTH;
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.key.expose(|a| {
            other
                .key
                .expose(|b| a.as_seed().as_slice().ct_eq(b.as_seed().as_slice()).into())
        })
    }
}

impl Eq for PrivateKey {}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PrivateKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let seed = Zeroizing::new(Seed::from(u.arbitrary::<[u8; PRIVATE_KEY_LENGTH]>()?));
        Ok(Self::expand(&seed))
    }
}

/// ML-DSA-65 Public Key.
///
/// Equality, ordering, and hashing use the encoded key. Every 1952-byte string is a valid
/// encoding (FIPS 204 `pkDecode` cannot fail), so decoding only fails on truncated input.
/// Decoding expands the public matrix once so that verification does not repeat it, and clones
/// share the expanded key.
#[derive(Clone, FixedArray)]
#[fixed_array(infallible)]
pub struct PublicKey {
    inner: Arc<PublicKeyInner>,
}

struct PublicKeyInner {
    raw: [u8; PUBLIC_KEY_LENGTH],
    key: VerifyingKey<MlDsa65>,
}

impl PublicKey {
    fn new(key: VerifyingKey<MlDsa65>) -> Self {
        Self {
            inner: Arc::new(PublicKeyInner {
                raw: key.encode().into(),
                key,
            }),
        }
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        value.public_key
    }
}

impl crate::PublicKey for PublicKey {}

impl crate::Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        let Some(signature) = sig.parse() else {
            return false;
        };
        self.inner
            .key
            .verify_with_context(&union_unique(namespace, msg), &[], &signature)
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.raw.write(buf);
    }
}

impl Read for PublicKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; PUBLIC_KEY_LENGTH]>::read(buf)?;
        let key = VerifyingKey::<MlDsa65>::decode((&raw).into());
        Ok(Self {
            inner: Arc::new(PublicKeyInner { raw, key }),
        })
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = PUBLIC_KEY_LENGTH;
}

impl Span for PublicKey {}

impl Array for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.raw == other.inner.raw
    }
}

impl Eq for PublicKey {}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.raw.cmp(&other.inner.raw)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.raw.hash(state);
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.inner.raw
    }
}

impl Deref for PublicKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner.raw
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.inner.raw))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.inner.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(PrivateKey::arbitrary(u)?.public_key)
    }
}

/// ML-DSA-65 Signature.
///
/// Decoding accepts only encodings that FIPS 204 `sigDecode` accepts, and `sigEncode` is the
/// inverse of `sigDecode` on those encodings, so a decoded signature has exactly one encoding.
/// Decoding copies the signature out of its buffer: signatures outlive the messages that carry
/// them, so a retained signature must not keep a pooled network buffer alive.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, FixedArray)]
pub struct Signature {
    raw: Bytes,
}

impl Signature {
    fn parse(&self) -> Option<::ml_dsa::Signature<MlDsa65>> {
        EncodedSignature::<MlDsa65>::slice_as_array(&self.raw).and_then(::ml_dsa::Signature::decode)
    }
}

impl crate::Signature for Signature {}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.raw);
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, SIGNATURE_LENGTH)?;
        let mut raw = [0u8; SIGNATURE_LENGTH];
        buf.copy_to_slice(&mut raw);
        let signature = Self {
            raw: Bytes::copy_from_slice(&raw),
        };
        if signature.parse().is_none() {
            return Err(CodecError::Invalid(NAME, "Invalid Signature"));
        }
        Ok(signature)
    }
}

impl FixedSize for Signature {
    const SIZE: usize = SIGNATURE_LENGTH;
}

impl Span for Signature {}

impl Array for Signature {}

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

impl Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer as _;

        let private_key = PrivateKey::arbitrary(u)?;
        let len = u.arbitrary::<usize>()? % 256;
        let message = u
            .arbitrary_iter()?
            .take(len)
            .collect::<Result<Vec<u8>, _>>()?;
        Ok(private_key.sign(&[], &message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Signer as _, Verifier as _};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::test_rng;
    use rand::RngExt as _;

    const NAMESPACE: &[u8] = b"test-namespace";
    const MESSAGE: &[u8] = b"test message";

    /// Offset of the hint encoding (`omega` indices followed by `k` cumulative counts).
    const HINT_OFFSET: usize = SIGNATURE_LENGTH - (55 + 6);

    fn private_key(seed: u8) -> PrivateKey {
        PrivateKey::decode([seed; PRIVATE_KEY_LENGTH].as_slice().to_vec()).unwrap()
    }

    fn signature_bytes() -> Vec<u8> {
        private_key(1).sign(NAMESPACE, MESSAGE).to_vec()
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = test_rng();
        let private_key = PrivateKey::random(&mut rng);
        let public_key = private_key.public_key();
        let signature = private_key.sign(NAMESPACE, MESSAGE);
        assert!(public_key.verify(NAMESPACE, MESSAGE, &signature));

        assert!(!public_key.verify(b"other-namespace", MESSAGE, &signature));
        assert!(!public_key.verify(NAMESPACE, b"other message", &signature));
        assert!(!public_key.verify(b"", MESSAGE, &signature));
        let other = PrivateKey::random(&mut rng).public_key();
        assert_ne!(public_key, other);
        assert!(!other.verify(NAMESPACE, MESSAGE, &signature));
    }

    #[test]
    fn test_namespace_is_bound() {
        // The namespace is length-prefixed, so moving bytes between namespace and message changes
        // the signed payload.
        let private_key = private_key(1);
        let signature = private_key.sign(b"ab", b"c");
        assert!(!private_key.public_key().verify(b"a", b"bc", &signature));
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let private_key = private_key(1);
        let public_key = private_key.public_key();
        let mut raw = signature_bytes();

        // Flipping a bit of the commitment hash keeps the encoding valid but breaks verification.
        raw[0] ^= 1;
        let signature = Signature::decode(raw).unwrap();
        assert!(!public_key.verify(NAMESPACE, MESSAGE, &signature));
    }

    #[test]
    fn test_codec_private_key() {
        let original = PrivateKey::random(test_rng());
        let encoded = original.encode();
        assert_eq!(encoded.len(), PRIVATE_KEY_LENGTH);
        assert_eq!(PrivateKey::SIZE, PRIVATE_KEY_LENGTH);

        let decoded = PrivateKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(original.public_key(), decoded.public_key());

        assert!(PrivateKey::decode(vec![0u8; PRIVATE_KEY_LENGTH - 1]).is_err());
        assert!(PrivateKey::decode(vec![0u8; PRIVATE_KEY_LENGTH + 1]).is_err());
    }

    #[test]
    fn test_codec_public_key() {
        let original = PrivateKey::random(test_rng()).public_key();
        let encoded = original.encode();
        assert_eq!(encoded.len(), PUBLIC_KEY_LENGTH);
        assert_eq!(PublicKey::SIZE, PUBLIC_KEY_LENGTH);

        let decoded = PublicKey::decode(encoded).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.as_ref(), original.as_ref());

        assert!(PublicKey::decode(vec![0u8; PUBLIC_KEY_LENGTH - 1]).is_err());
        assert!(PublicKey::decode(vec![0u8; PUBLIC_KEY_LENGTH + 1]).is_err());
    }

    #[test]
    fn test_public_key_decoding_is_infallible() {
        let signature = private_key(1).sign(NAMESPACE, MESSAGE);
        let mut rng = test_rng();
        let mut random = [0u8; PUBLIC_KEY_LENGTH];
        rng.fill(&mut random[..]);
        for raw in [
            [0u8; PUBLIC_KEY_LENGTH],
            [0xFFu8; PUBLIC_KEY_LENGTH],
            random,
        ] {
            let public_key = PublicKey::from(raw);
            assert_eq!(public_key.as_ref(), raw.as_slice());
            assert_eq!(public_key.encode().as_ref(), raw.as_slice());
            assert!(!public_key.verify(NAMESPACE, MESSAGE, &signature));
        }
    }

    #[test]
    fn test_codec_signature() {
        let original = private_key(1).sign(NAMESPACE, MESSAGE);
        let encoded = original.encode();
        assert_eq!(encoded.len(), SIGNATURE_LENGTH);
        assert_eq!(Signature::SIZE, SIGNATURE_LENGTH);

        let decoded = Signature::decode(encoded.clone()).unwrap();
        assert_eq!(original, decoded);

        // Decoding copies out of the input allocation so the input can be released.
        assert_ne!(decoded.as_ref().as_ptr(), encoded.as_ref().as_ptr());
    }

    #[test]
    fn test_decode_signature_rejects_wrong_length() {
        let raw = signature_bytes();
        assert!(matches!(
            Signature::decode(raw[..SIGNATURE_LENGTH - 1].to_vec()),
            Err(CodecError::EndOfBuffer)
        ));
        let mut extended = raw;
        extended.push(0);
        assert!(matches!(
            Signature::decode(extended),
            Err(CodecError::ExtraData(1))
        ));
    }

    #[test]
    fn test_decode_signature_rejects_malformed_encodings() {
        let invalid = |raw: Vec<u8>| {
            assert!(matches!(
                Signature::decode(raw),
                Err(CodecError::Invalid(NAME, "Invalid Signature"))
            ));
        };

        // Uniformly random bytes and all ones.
        let mut random = vec![0u8; SIGNATURE_LENGTH];
        test_rng().fill(random.as_mut_slice());
        invalid(random);
        invalid(vec![0xFF; SIGNATURE_LENGTH]);

        // A response coefficient outside the permitted range (the first coefficient encodes to
        // gamma1).
        let mut raw = signature_bytes();
        raw[48] = 0;
        raw[49] = 0;
        raw[50] &= 0xF0;
        invalid(raw);

        // A hint count exceeding omega.
        let mut raw = signature_bytes();
        raw[SIGNATURE_LENGTH - 1] = 0xFF;
        invalid(raw);

        // Decreasing hint counts.
        let mut raw = signature_bytes();
        raw[SIGNATURE_LENGTH - 6] = raw[SIGNATURE_LENGTH - 1] + 1;
        invalid(raw);

        // A non-zero hint index beyond the last hint.
        let mut raw = signature_bytes();
        let hints = raw[SIGNATURE_LENGTH - 1] as usize;
        assert!(hints < 55);
        raw[HINT_OFFSET + hints] = 1;
        invalid(raw);

        // Hint indices of a polynomial that are not strictly increasing.
        let mut raw = signature_bytes();
        let mut start = 0;
        let mut tampered = false;
        for count in SIGNATURE_LENGTH - 6..SIGNATURE_LENGTH {
            let end = raw[count] as usize;
            if end - start >= 2 {
                raw[HINT_OFFSET + start + 1] = raw[HINT_OFFSET + start];
                tampered = true;
                break;
            }
            start = end;
        }
        assert!(tampered);
        invalid(raw);
    }

    #[test]
    fn test_determinism() {
        // The same seed yields the same key pair.
        let a = private_key(7);
        let b = private_key(7);
        assert_eq!(a, b);
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a, private_key(8));
        assert_eq!(PrivateKey::from_seed(3), PrivateKey::from_seed(3));
        assert_ne!(PrivateKey::from_seed(3), PrivateKey::from_seed(4));

        // Signing is deterministic.
        assert_eq!(a.sign(NAMESPACE, MESSAGE), b.sign(NAMESPACE, MESSAGE));
        assert_ne!(a.sign(NAMESPACE, MESSAGE), a.sign(NAMESPACE, b"other"));
    }

    #[test]
    fn test_private_key_redacted() {
        let private_key = PrivateKey::random(test_rng());
        let seed = commonware_formatting::hex(&private_key.encode());
        let debug = format!("{:?}", private_key);
        let display = format!("{}", private_key);
        assert!(debug.contains("REDACTED"));
        assert!(display.contains("REDACTED"));
        assert!(!debug.contains(&seed));
        assert!(!display.contains(&seed));
    }

    #[test]
    fn test_from_private_key_to_public_key() {
        let private_key = PrivateKey::random(test_rng());
        assert_eq!(private_key.public_key(), PublicKey::from(private_key));
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn test_aws_lc_rs_interoperability() {
        use aws_lc_rs::{
            signature::{KeyPair as _, UnparsedPublicKey},
            unstable::signature::{ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair},
        };

        for seed in 0..4u8 {
            let private_key = private_key(seed);
            let public_key = private_key.public_key();
            let key_pair = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &[seed; 32]).unwrap();

            // Key generation from the same seed yields the same public key.
            assert_eq!(key_pair.public_key().as_ref(), public_key.as_ref());

            // aws-lc-rs accepts our deterministic signature over the namespaced payload.
            let payload = union_unique(NAMESPACE, MESSAGE);
            let signature = private_key.sign(NAMESPACE, MESSAGE);
            UnparsedPublicKey::new(&ML_DSA_65, public_key.as_ref())
                .verify(&payload, signature.as_ref())
                .unwrap();

            // We accept a (randomized) aws-lc-rs signature over the namespaced payload.
            let mut raw = [0u8; SIGNATURE_LENGTH];
            assert_eq!(key_pair.sign(&payload, &mut raw).unwrap(), SIGNATURE_LENGTH);
            let signature = Signature::decode(raw.as_slice().to_vec()).unwrap();
            assert!(public_key.verify(NAMESPACE, MESSAGE, &signature));
            assert!(!public_key.verify(NAMESPACE, b"other message", &signature));
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PrivateKey> => 1024,
            CodecConformance<PublicKey> => 1024,
            CodecConformance<Signature> => 1024,
        }
    }
}
