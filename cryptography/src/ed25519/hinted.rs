//! Hinted Ed25519 variant of the [crate::Verifier] and [crate::Signer] traits.
//!
//! Signatures carry a committed decompression hint for `R` (the affine `x`
//! coordinate) and public keys are carried decompressed (`x || y`), so
//! verification recovers points with an on-curve check instead of a square root.
//!
//! Because the hint is committed in the signature encoding, validity is a
//! deterministic function of the bytes: an invalid hint is simply an invalid
//! signature, with no fallback. This variant follows the same [ZIP215] rules as
//! [`super::standard`] except that the non-canonical `x = 0`, `sign = 1`
//! encoding of `R`, and non-canonical hint/key encodings, are rejected.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{ed25519::hinted, PrivateKey as _, PublicKey as _, Verifier as _, Signer as _};
//! use commonware_math::algebra::Random;
//! use rand::rngs::OsRng;
//!
//! let mut signer = hinted::PrivateKey::random(&mut OsRng);
//! let namespace = b"demo";
//! let msg = b"hello, world!";
//! let signature = signer.sign(namespace, msg);
//! assert!(signer.public_key().verify(namespace, msg, &signature));
//! ```
//!
//! [ZIP215]: https://zips.z.cash/zip-0215

use crate::{
    ed25519::core::{self as ed_core, VerificationKey},
    BatchVerifier, Secret,
};
#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedArray, FixedSize, Read, ReadExt, Write};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_utils::{union_unique, Array, Span};
use core::{
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use std::borrow::Cow;
use zeroize::Zeroizing;

const CURVE_NAME: &str = "ed25519-hinted";
const PRIVATE_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 64; // x || y
const SIGNATURE_LENGTH: usize = 96; // R || s || x

/// Hinted Ed25519 Private Key.
///
/// The key material is identical to [`super::standard::PrivateKey`]; signing
/// additionally derives and commits the decompression hint for `R`.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    key: Secret<ed_core::SigningKey>,
}

impl crate::PrivateKey for PrivateKey {}

impl crate::Signer for PrivateKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        self.sign_inner(Some(namespace), msg)
    }

    fn public_key(&self) -> Self::PublicKey {
        self.key
            .expose(|key| PublicKey::from_verification_key(key.verification_key()))
    }
}

impl PrivateKey {
    #[inline(always)]
    fn sign_inner(&self, namespace: Option<&[u8]>, msg: &[u8]) -> Signature {
        let payload = namespace
            .map(|namespace| Cow::Owned(union_unique(namespace, msg)))
            .unwrap_or_else(|| Cow::Borrowed(msg));
        let signature = self.key.expose(|key| key.sign(&payload));
        Signature::from_ed_signature(signature)
    }
}

impl Random for PrivateKey {
    fn random(rng: impl CryptoRngCore) -> Self {
        Self {
            key: Secret::new(ed_core::SigningKey::new(rng)),
        }
    }
}

impl Write for PrivateKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.expose(|key| key.as_bytes().write(buf));
    }
}

impl Read for PrivateKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = Zeroizing::new(<[u8; Self::SIZE]>::read(buf)?);
        Ok(Self {
            key: Secret::new(ed_core::SigningKey::from(*raw)),
        })
    }
}

impl FixedSize for PrivateKey {
    const SIZE: usize = PRIVATE_KEY_LENGTH;
}

impl From<ed_core::SigningKey> for PrivateKey {
    fn from(key: ed_core::SigningKey) -> Self {
        Self {
            key: Secret::new(key),
        }
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
        use rand::{rngs::StdRng, SeedableRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        Ok(Self::random(&mut rand))
    }
}

#[cfg(test)]
impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.key
            .expose(|key1| other.key.expose(|key2| key1.as_bytes() == key2.as_bytes()))
    }
}

/// Hinted Ed25519 Public Key, carried decompressed as `x || y`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, FixedArray)]
pub struct PublicKey {
    raw: [u8; PUBLIC_KEY_LENGTH],
    key: VerificationKey,
}

impl PublicKey {
    fn from_verification_key(key: VerificationKey) -> Self {
        let (x, y) = key.coordinates();
        let mut raw = [0u8; PUBLIC_KEY_LENGTH];
        raw[..32].copy_from_slice(&x);
        raw[32..].copy_from_slice(&y);
        Self { raw, key }
    }

    /// The verification key, for queueing into a [`Batch`].
    const fn verification_key(&self) -> VerificationKey {
        self.key
    }

    #[inline(always)]
    fn verify_inner(&self, namespace: Option<&[u8]>, msg: &[u8], sig: &Signature) -> bool {
        let payload = namespace
            .map(|namespace| Cow::Owned(union_unique(namespace, msg)))
            .unwrap_or_else(|| Cow::Borrowed(msg));
        let (r, s, x) = sig.parts();
        self.key.verify_hinted(&r, &s, &x, &payload).is_ok()
    }
}

impl From<PrivateKey> for PublicKey {
    fn from(value: PrivateKey) -> Self {
        value
            .key
            .expose(|key| Self::from_verification_key(key.verification_key()))
    }
}

impl crate::PublicKey for PublicKey {}

impl crate::Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        self.verify_inner(Some(namespace), msg, sig)
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
        let mut x = [0u8; 32];
        x.copy_from_slice(&raw[..32]);
        let mut y = [0u8; 32];
        y.copy_from_slice(&raw[32..]);
        let result = VerificationKey::from_coordinates(&x, &y);
        #[cfg(feature = "std")]
        let key = result.map_err(|e| CodecError::Wrapped(CURVE_NAME, e.into()))?;
        #[cfg(not(feature = "std"))]
        let key = result
            .map_err(|e| CodecError::Wrapped(CURVE_NAME, alloc::format!("{:?}", e).into()))?;
        // Reject non-canonical coordinate encodings so each key has a unique encoding.
        let (cx, cy) = key.coordinates();
        if cx != x || cy != y {
            return Err(CodecError::Invalid(CURVE_NAME, "non-canonical public key"));
        }
        Ok(Self { raw, key })
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = PUBLIC_KEY_LENGTH;
}

impl Span for PublicKey {}

impl Array for PublicKey {}

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

impl Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", Hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer;
        use rand::{rngs::StdRng, SeedableRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        Ok(PrivateKey::random(&mut rand).public_key())
    }
}

/// Hinted Ed25519 Signature, encoded as `R || s || x`, where `x` is the
/// committed decompression hint for `R`.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, FixedArray)]
pub struct Signature {
    raw: [u8; SIGNATURE_LENGTH],
}

impl Signature {
    fn from_ed_signature(signature: ed_core::Signature) -> Self {
        let r_s = signature.to_bytes();
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&r_s[..32]);
        let x =
            VerificationKey::decompression_hint(&r_bytes).expect("freshly signed R decompresses");
        let mut raw = [0u8; SIGNATURE_LENGTH];
        raw[..64].copy_from_slice(&r_s);
        raw[64..].copy_from_slice(&x);
        Self { raw }
    }

    /// `(R, s, x)` components.
    fn parts(&self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut r = [0u8; 32];
        r.copy_from_slice(&self.raw[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&self.raw[32..64]);
        let mut x = [0u8; 32];
        x.copy_from_slice(&self.raw[64..]);
        (r, s, x)
    }
}

impl crate::Signature for Signature {}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.raw.write(buf);
    }
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let raw = <[u8; Self::SIZE]>::read(buf)?;
        Ok(Self { raw })
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
        use crate::Signer;
        use rand::{rngs::StdRng, SeedableRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        let private_key = PrivateKey::random(&mut rand);
        let len = u.arbitrary::<usize>()? % 256;
        let message = u
            .arbitrary_iter()?
            .take(len)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(private_key.sign(&[], &message))
    }
}

/// Hinted Ed25519 Batch Verifier.
pub struct Batch {
    verifier: ed_core::batch::Verifier,
}

impl BatchVerifier for Batch {
    type PublicKey = PublicKey;

    fn new() -> Self {
        Self {
            verifier: ed_core::batch::Verifier::new(),
        }
    }

    fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        self.add_inner(Some(namespace), message, public_key, signature)
    }

    fn verify<R: CryptoRngCore>(self, rng: &mut R, strategy: &impl Strategy) -> bool {
        self.verifier.verify(rng, strategy).is_ok()
    }
}

impl Batch {
    #[inline(always)]
    fn add_inner(
        &mut self,
        namespace: Option<&[u8]>,
        message: &[u8],
        public_key: &PublicKey,
        signature: &Signature,
    ) -> bool {
        let payload = namespace
            .map(|ns| Cow::Owned(union_unique(ns, message)))
            .unwrap_or_else(|| Cow::Borrowed(message));
        let (r, s, x) = signature.parts();
        self.verifier
            .queue_hinted(public_key.verification_key(), r, s, x, &payload);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ed25519::standard, Signer as _, Verifier as _};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    fn keypair() -> (PrivateKey, PublicKey) {
        let sk = PrivateKey::random(&mut test_rng());
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn sign_and_verify() {
        let (sk, pk) = keypair();
        let sig = sk.sign(b"ns", b"hello");
        assert!(pk.verify(b"ns", b"hello", &sig));
        assert!(!pk.verify(b"ns", b"goodbye", &sig));
        assert!(!pk.verify(b"other", b"hello", &sig));
    }

    /// A hinted signature embeds the same (R, s) a standard signature would
    /// produce, and the embedded hint is the true decompression of R.
    #[test]
    fn agrees_with_standard() {
        let bytes = PrivateKey::random(&mut test_rng())
            .key
            .expose(|k| *k.as_bytes());
        let hinted_sk = PrivateKey::from(ed_core::SigningKey::from(bytes));
        let standard_sk = standard::PrivateKey::decode(bytes.as_ref()).unwrap();

        let hinted_sig = hinted_sk.sign(b"ns", b"msg");
        let standard_sig = standard_sk.sign(b"ns", b"msg");
        // The R || s prefix is identical.
        assert_eq!(&hinted_sig.raw[..64], standard_sig.as_ref());
        // And the standard public key verifies the standard part.
        assert!(standard_sk
            .public_key()
            .verify(b"ns", b"msg", &standard_sig));
        assert!(hinted_sk.public_key().verify(b"ns", b"msg", &hinted_sig));
    }

    #[test]
    fn corrupted_hint_rejected() {
        let (sk, pk) = keypair();
        let mut sig = sk.sign(b"ns", b"msg");
        sig.raw[64] ^= 1; // flip a hint byte
        assert!(!pk.verify(b"ns", b"msg", &sig));
    }

    #[test]
    fn non_canonical_hint_rejected() {
        let (sk, pk) = keypair();
        let mut sig = sk.sign(b"ns", b"msg");
        sig.raw[95] |= 0x80; // set the ignored high bit of x (non-canonical)
        assert!(!pk.verify(b"ns", b"msg", &sig));
    }

    #[test]
    fn batch_verify_valid() {
        let mut batch = Batch::new();
        for i in 0..16u8 {
            let (sk, pk) = keypair();
            let msg = [i; 8];
            let sig = sk.sign(b"ns", &msg);
            assert!(batch.add(b"ns", &msg, &pk, &sig));
        }
        assert!(batch.verify(&mut test_rng(), &Sequential));
    }

    #[test]
    fn batch_verify_invalid() {
        let mut batch = Batch::new();
        let (sk, pk) = keypair();
        let sig = sk.sign(b"ns", b"good");
        assert!(batch.add(b"ns", b"good", &pk, &sig));
        // One corrupted signature spoils the batch.
        let (sk2, pk2) = keypair();
        let mut bad = sk2.sign(b"ns", b"bad");
        bad.raw[0] ^= 1;
        assert!(batch.add(b"ns", b"bad", &pk2, &bad));
        assert!(!batch.verify(&mut test_rng(), &Sequential));
    }

    #[test]
    fn batch_of_one() {
        let (sk, pk) = keypair();
        let sig = sk.sign(b"ns", b"solo");
        let mut batch = Batch::new();
        assert!(batch.add(b"ns", b"solo", &pk, &sig));
        assert!(batch.verify(&mut test_rng(), &Sequential));
    }

    #[test]
    fn codec_roundtrip() {
        let (sk, pk) = keypair();
        let sig = sk.sign(b"ns", b"msg");

        let sk2 = PrivateKey::decode(sk.encode()).unwrap();
        assert_eq!(sk, sk2);
        assert_eq!(pk.encode().len(), PUBLIC_KEY_LENGTH);
        let pk2 = PublicKey::decode(pk.encode()).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sig.encode().len(), SIGNATURE_LENGTH);
        let sig2 = Signature::decode(sig.encode()).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn non_canonical_public_key_rejected() {
        let (_, pk) = keypair();
        let mut raw = pk.encode().to_vec();
        raw[31] |= 0x80; // set ignored high bit of x
        assert!(PublicKey::decode(raw.as_ref()).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<PrivateKey>,
            CodecConformance<PublicKey>,
            CodecConformance<Signature>,
        }
    }
}
