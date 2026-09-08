//! Ed25519 signing keys, signatures, and verification.
//!
//! # Validation criteria (ZIP215)
//!
//! Signature validation follows [ZIP215], the criteria that make Ed25519 safe for consensus:
//!
//! - The point encodings of the verifying key `A` and the signature component `R` are accepted
//!   even when non-canonical (a `y` coordinate at or above `p`, or a negative-zero `x`), as long
//!   as they decode to a curve point.
//! - The scalar component `s` must be canonical (`s < L`), ruling out signature malleability.
//! - The verification equation is cofactored: `[8](s·B - R - H(R || A || M)·A) == identity`.
//!
//! [`VerifyingKey::verify`] and [`BatchVerifier::verify`] apply the same criteria.
//! A non-empty batch of at most `u32::MAX` signatures is always accepted when every signature
//! verifies individually. Because batch verification checks a randomized linear combination, an
//! invalid batch may be accepted with probability about `2^-128`, provided each verification
//! call draws a fresh seed from an RNG unpredictable to whoever assembled the batch. See
//! [this post] for why these criteria matter.
//!
//! [this post]: https://hdevalence.ca/blog/2020-10-04-its-25519am
//! [ZIP215]: https://zips.z.cash/zip-0215

mod core;

use self::core::Scalar;
use crate::curve::GAffine;
use ::core::{
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Decode, DecodeWith, EncodeSize, Error as CodecError, FixedSize, Read, Write, types::lazy::Lazy,
};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_utils::union_unique;
use rand_core::CryptoRng;
use sha2::{
    Digest,
    digest::{FixedOutput, Update},
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// An Ed25519 signing key.
///
/// Secret material is zeroized when the key is dropped.
/// Serialization writes the raw secret seed, so callers must protect the encoded bytes as
/// secret key material.
#[derive(ZeroizeOnDrop)]
pub struct SigningKey {
    /// When serializing, we want to just write the seed, so we keep it around.
    seed: [u8; 32],
    /// The private prefix we use to derive a deterministic nonce for each message.
    prefix: [u8; 32],
    /// The pruned secret scalar, reduced modulo the basepoint order.
    scalar: Scalar,
    /// The verifying key derived from the secret scalar.
    #[zeroize(skip)]
    verifying_key: VerifyingKey,
}

// Private methods.
impl SigningKey {
    fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        // Following: https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5.
        // The first half becomes our secret scalar material, while the second half
        // is the private prefix we use to derive deterministic nonces.
        let h: Zeroizing<[u8; 64]> =
            Zeroizing::new(sha2::Sha512::new().chain(&seed[..]).finalize_fixed().into());
        let mut scalar_le_bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(h[..32].try_into().expect("h is 64 bytes"));
        let prefix: Zeroizing<[u8; 32]> =
            Zeroizing::new(h[32..].try_into().expect("h is 64 bytes"));
        // We want the integer represented by these little-endian bytes to be a
        // multiple of the curve's cofactor, 8, so we "clamp" it by zeroing its
        // three least-significant bits. This is part of Ed25519 key derivation too,
        // not just key exchange.
        scalar_le_bytes[0] &= 0b1111_1000;
        // We also want the scalar to fit in 255 bits, so we unset bit 255. This
        // doesn't put it below L; scalar-field arithmetic still has to reduce it
        // modulo L.
        scalar_le_bytes[31] &= 0b0111_1111;
        // The RFC also requires us to set bit 254, giving the scalar a fixed 255-bit
        // length. Among other things, this forces scalar-multiplication implementations
        // that start at the highest set bit to use the same number of iterations. It
        // doesn't make a variable-time implementation safe by itself.
        scalar_le_bytes[31] |= 0b0100_0000;
        let mut wide_scalar = Zeroizing::new([0u8; 64]);
        wide_scalar[..32].copy_from_slice(&scalar_le_bytes[..]);
        let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide_scalar));
        let point = GAffine::BASEPOINT
            .to_extended()
            .scalar_mul_secret(&scalar_le_bytes)
            .to_affine();
        let verifying_key = VerifyingKey {
            bytes: core::VerifyingKeyBytes::new(point.to_bytes()),
            point,
        };

        Self {
            seed: *seed,
            prefix: *prefix,
            scalar: *scalar,
            verifying_key,
        }
    }

    fn sign_message(&self, msg: &[u8]) -> Signature {
        let nonce_digest: Zeroizing<[u8; 64]> = Zeroizing::new(
            sha2::Sha512::new()
                .chain(self.prefix.as_slice())
                .chain(msg)
                .finalize_fixed()
                .into(),
        );
        let nonce = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&nonce_digest));
        let nonce_bytes = Zeroizing::new(nonce.to_bytes());
        let r_bytes = GAffine::BASEPOINT
            .to_extended()
            .scalar_mul_secret(&nonce_bytes)
            .to_bytes();

        let challenge_digest: [u8; 64] = sha2::Sha512::new()
            .chain(r_bytes)
            .chain(self.verifying_key.bytes.as_bytes())
            .chain(msg)
            .finalize_fixed()
            .into();
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_digest);
        let challenge_scalar = Zeroizing::new(challenge.mul_mod_l(&self.scalar));
        let s_bytes = nonce.add_mod_l(&challenge_scalar).to_bytes();

        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&r_bytes);
        bytes[32..].copy_from_slice(&s_bytes);
        Signature { bytes }
    }
}

impl Random for SigningKey {
    fn random(mut rng: impl rand_core::CryptoRng) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut seed[..]);
        Self::from_seed(*seed)
    }
}

impl Write for SigningKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.seed.write(buf);
    }
}

impl FixedSize for SigningKey {
    const SIZE: usize = 32;
}

impl Read for SigningKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let seed = Zeroizing::new(<[u8; Self::SIZE]>::read_cfg(buf, cfg)?);
        Ok(Self::from_seed(*seed))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for SigningKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let seed: Zeroizing<[u8; Self::SIZE]> = Zeroizing::new(u.arbitrary()?);
        Ok(Self::from_seed(*seed))
    }
}

// Public methods.
impl SigningKey {
    /// The verifying key associated with this signing key.
    ///
    /// Signatures produced by this signing key can be verified using this public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key.clone()
    }

    /// Signs a namespaced message using deterministic Ed25519.
    ///
    /// The namespace is committed to the signature to prevent its reuse in another context.
    /// Signing is deterministic per [RFC 8032]: the nonce is derived from the key and the
    /// message, so signing the same message twice yields the same signature and no randomness
    /// is consumed.
    ///
    /// # Panics
    ///
    /// Panics if `namespace` is longer than `u32::MAX` bytes.
    ///
    /// [RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
    pub fn sign(&self, namespace: &[u8], msg: &[u8]) -> Signature {
        let msg = union_unique(namespace, msg);
        self.sign_message(&msg)
    }

    /// Signs an unframed message for raw Ed25519 test-vector checks.
    #[cfg(test)]
    pub(crate) fn sign_raw(&self, msg: &[u8]) -> Signature {
        self.sign_message(msg)
    }
}

/// A public key used to check signatures.
///
/// Decoding validates that the encoding represents a curve point under ZIP215.
/// Use [`Lazy<VerifyingKey>`] to defer this validation and [`BatchVerifier::add_lazy`] to
/// populate the lazy value's cache during batch verification.
/// Equality, ordering, and hashing use the original encoding: distinct encodings of the same
/// point are distinct keys, and verification hashes the received bytes as required by ZIP215.
#[derive(Clone)]
pub struct VerifyingKey {
    /// The encoded point.
    ///
    /// Verification and key identity preserve this encoding, including non-canonical aliases.
    bytes: core::VerifyingKeyBytes,
    /// The validated point associated with these exact bytes.
    point: GAffine,
}

/// A reusable point-decoding result for one exact public-key encoding.
///
/// This context preserves both successful and failed point decoding. It does not represent
/// a signature-verification result. Contexts are constructed by the batch verifier, and a
/// different input encoding always falls back to ordinary decoding.
pub struct VerifyingKeyContext {
    bytes: [u8; 32],
    point: Option<GAffine>,
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for VerifyingKey {}

impl PartialOrd for VerifyingKey {
    fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VerifyingKey {
    fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl Hash for VerifyingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(self.bytes.as_bytes()))
    }
}

impl Display for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(self.bytes.as_bytes()))
    }
}

impl AsRef<[u8]> for VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

impl Write for VerifyingKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.as_bytes().write(buf);
    }
}

impl FixedSize for VerifyingKey {
    const SIZE: usize = 32;
}

impl Read for VerifyingKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let bytes = <[u8; Self::SIZE]>::read_cfg(buf, cfg)?;
        Self::from_point(bytes, GAffine::decompress(&bytes))
    }
}

impl DecodeWith for VerifyingKey {
    type Context = VerifyingKeyContext;

    fn decode_with(
        bytes: &[u8],
        cfg: &Self::Cfg,
        context: &Self::Context,
    ) -> Result<Self, CodecError> {
        if bytes == context.bytes {
            Self::from_point(context.bytes, context.point)
        } else {
            Self::decode_cfg(bytes, cfg)
        }
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for VerifyingKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let bytes = u.arbitrary()?;
        let point = GAffine::decompress(&bytes).ok_or(arbitrary::Error::IncorrectFormat)?;
        Ok(Self {
            bytes: core::VerifyingKeyBytes::new(bytes),
            point,
        })
    }
}

impl VerifyingKey {
    /// Associates an exact encoding with its point-decoding result.
    fn from_point(bytes: [u8; 32], point: Option<GAffine>) -> Result<Self, CodecError> {
        let point = point.ok_or(CodecError::Invalid(
            "curve25519::VerifyingKey",
            "Invalid point encoding",
        ))?;
        Ok(Self {
            bytes: core::VerifyingKeyBytes::new(bytes),
            point,
        })
    }

    fn verify_message(&self, msg: &[u8], sig: &Signature) -> bool {
        let r_bytes: [u8; 32] = sig.bytes[..32].try_into().expect("signature is 64 bytes");
        let s_bytes: [u8; 32] = sig.bytes[32..].try_into().expect("signature is 64 bytes");
        let Some(s) = Scalar::from_canonical_bytes(&s_bytes) else {
            return false;
        };
        let Some(r) = GAffine::decompress(&r_bytes) else {
            return false;
        };
        let a = self.point.to_extended();

        let digest: [u8; 64] = sha2::Sha512::new()
            .chain(r_bytes)
            .chain(self.bytes.as_bytes())
            .chain(msg)
            .finalize_fixed()
            .into();
        let k = Scalar::from_bytes_mod_order_wide(&digest);

        let sb = GAffine::BASEPOINT.to_extended().scalar_mul(s.bits_be());
        let ka = a.scalar_mul(k.bits_be());
        sb.add(ka.add_mixed(r).negate())
            .mul_by_cofactor()
            .is_identity()
    }
}

// Public methods.
impl VerifyingKey {
    /// Verifies `sig` over the namespaced message, per the [module's validation
    /// criteria](self).
    ///
    /// # Panics
    ///
    /// Panics if `namespace` is longer than `u32::MAX` bytes.
    #[must_use]
    pub fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Signature) -> bool {
        let msg = union_unique(namespace, msg);
        self.verify_message(&msg, sig)
    }

    /// Verifies an unframed message for raw Ed25519 test-vector checks.
    #[cfg(test)]
    pub(crate) fn verify_raw(&self, msg: &[u8], sig: &Signature) -> bool {
        self.verify_message(msg, sig)
    }
}

/// An Ed25519 signature.
///
/// For an honestly generated [`VerifyingKey`], successful verification demonstrates approval by
/// the holder of the corresponding [`SigningKey`]. A maliciously generated verifying key can
/// admit a signature that verifies for any message.
///
/// Decoding accepts any 64 bytes. Point decoding and scalar canonicality are checked during
/// verification. Equality, ordering, and hashing compare the original encoding.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature {
    bytes: [u8; 64],
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for Signature {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.write(buf);
    }
}

impl FixedSize for Signature {
    const SIZE: usize = 64;
}

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            bytes: <[u8; Self::SIZE]>::read_cfg(buf, cfg)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            bytes: u.arbitrary()?,
        })
    }
}

/// Inputs retained for batch verification.
///
/// The encoded key is the batch pipeline's authoritative identity.
struct BatchItem {
    message: Vec<u8>,
    public_key: core::VerifyingKeyBytes,
    signature: core::Signature,
}

/// A batch verification context.
///
/// Lazy keys are borrowed so point decoding can populate caches in the caller's retained objects.
pub struct BatchVerifier<'a> {
    items: Vec<BatchItem>,
    lazy_keys: Vec<Option<&'a Lazy<VerifyingKey>>>,
    valid: bool,
}

impl core::KeyCache for BatchVerifier<'_> {
    fn get(&self, index: usize) -> Option<Option<GAffine>> {
        self.lazy_keys
            .get(index)?
            .as_ref()?
            .get_cached()
            .map(|key| key.map(|key| key.point))
    }

    fn store(&self, index: usize, bytes: &[u8; 32], point: Option<GAffine>) {
        if let Some(Some(key)) = self.lazy_keys.get(index) {
            key.get_with(&VerifyingKeyContext {
                bytes: *bytes,
                point,
            });
        }
    }
}

impl<'a> BatchVerifier<'a> {
    /// Creates a verifier with space for `capacity` signatures.
    ///
    /// `capacity` is a trusted allocation hint. Bound externally supplied counts before passing
    /// them here.
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
            lazy_keys: Vec::new(),
            valid: true,
        }
    }

    /// Queues a signature for verification over the namespaced message.
    ///
    /// # Panics
    ///
    /// Panics if `namespace` is longer than `u32::MAX` bytes.
    pub fn add(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        public_key: &VerifyingKey,
        signature: &Signature,
    ) {
        self.items.push(BatchItem {
            message: union_unique(namespace, message),
            public_key: public_key.bytes,
            signature: core::Signature::from_bytes(signature.bytes),
        });
    }

    /// Queues a signature without forcing decoding of its lazy public key.
    ///
    /// Verification caches each point-decoding result in the original lazy key. Repeated key
    /// encodings share the decompression work, and later [`Lazy::get`] calls reuse the result.
    /// A batch rejected before its point-processing phase can leave keys uninitialized.
    /// Incorrectly sized encodings invalidate the batch.
    ///
    /// # Panics
    ///
    /// Panics if `namespace` is longer than `u32::MAX` bytes.
    pub fn add_lazy(
        &mut self,
        namespace: &[u8],
        message: &[u8],
        public_key: &'a Lazy<VerifyingKey>,
        signature: &Signature,
    ) {
        self.add_lazy_message(union_unique(namespace, message), public_key, signature);
    }

    /// Queues the original key encoding and retains its cache destination.
    fn add_lazy_message(
        &mut self,
        message: Vec<u8>,
        public_key: &'a Lazy<VerifyingKey>,
        signature: &Signature,
    ) {
        if public_key.encode_size() != VerifyingKey::SIZE {
            self.valid = false;
            return;
        }
        let mut bytes = [0u8; VerifyingKey::SIZE];
        public_key.write(&mut bytes.as_mut_slice());
        self.lazy_keys.resize(self.items.len(), None);
        self.lazy_keys.push(Some(public_key));
        self.items.push(BatchItem {
            message,
            public_key: core::VerifyingKeyBytes::new(bytes),
            signature: core::Signature::from_bytes(signature.bytes),
        });
    }

    /// Queues an unframed message with a lazy key for raw Ed25519 test vectors.
    #[cfg(test)]
    pub(crate) fn add_lazy_raw(
        &mut self,
        message: &[u8],
        public_key: &'a Lazy<VerifyingKey>,
        signature: &Signature,
    ) {
        self.add_lazy_message(message.to_vec(), public_key, signature);
    }

    /// Checks all the signatures in the batch.
    ///
    /// Empty batches and batches containing more than `u32::MAX` signatures are rejected. Within
    /// that limit, a non-empty batch is always accepted when every signature verifies individually
    /// under the [module's validation criteria](self). Because this checks a randomized linear
    /// combination, an invalid batch may be accepted when the random weights make the combined
    /// equation hold, an event of negligible probability (about `2^-128`).
    ///
    /// This bound requires an RNG unpredictable to whoever assembled the batch. A predictable
    /// `rng` lets an attacker construct an invalid batch that passes verification.
    #[must_use]
    pub fn verify(self, rng: &mut impl CryptoRng, strategy: &impl Strategy) -> bool {
        if !self.valid {
            return false;
        }
        let items = self
            .items
            .iter()
            .map(|item| (&item.public_key, &item.signature, item.message.as_slice()));
        if self.lazy_keys.is_empty() {
            core::verify_batch_bytes(rng, items, strategy)
        } else {
            core::verify_batch_bytes_cached(rng, items, strategy, &self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BatchItem, BatchVerifier, SigningKey, VerifyingKey, VerifyingKeyContext};
    use crate::curve::GAffine;
    use commonware_codec::{DecodeExt, DecodeWith, Encode, types::lazy::Lazy};
    use commonware_parallel::{Rayon, Sequential, Strategy};
    use commonware_utils::{NZUsize, test_rng};

    #[test]
    fn batch_items_do_not_retain_decoded_key_cache() {
        assert_eq!(
            core::mem::size_of::<BatchItem>(),
            core::mem::size_of::<(Vec<u8>, [u8; 32], super::core::Signature)>(),
        );
    }

    #[test]
    fn empty_batch_is_invalid() {
        assert!(!BatchVerifier::new(0).verify(&mut test_rng(), &Sequential));
    }

    #[test]
    fn contextual_key_decoding_preserves_the_exact_encoding() {
        for bytes in crate::test::ZIP215_POINTS {
            let context = VerifyingKeyContext {
                bytes,
                point: GAffine::decompress(&bytes),
            };
            let lazy = Lazy::<VerifyingKey>::deferred(&mut bytes.as_slice(), ());
            let key = lazy.get_with(&context).unwrap();
            assert_eq!(key.as_ref(), bytes);
            assert_eq!(lazy.encode().as_ref(), bytes);
            assert!(::core::ptr::eq(key, lazy.get().unwrap()));

            let other_bytes = SigningKey::from_seed([42; 32]).verifying_key().encode();
            let other = Lazy::<VerifyingKey>::deferred(&mut other_bytes.as_ref(), ());
            assert_eq!(
                other.get_with(&context),
                VerifyingKey::decode(other_bytes).ok().as_ref(),
            );

            let mut malformed = [0u8; 32];
            malformed[0] = 2;
            assert!(VerifyingKey::decode_with(&malformed, &(), &context).is_err());
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert!(VerifyingKey::decode_with(&trailing, &(), &context).is_err());
        }
    }

    #[test]
    fn lazy_batch_populates_retained_keys_and_preserves_mixed_indices() {
        const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_LAZY_KEYS_TEST";
        fn run(strategy: &impl Strategy) {
            let fixtures = [42, 43, 44].map(|seed| {
                let signing_key = SigningKey::from_seed([seed; 32]);
                (
                    signing_key.verifying_key(),
                    signing_key.sign(NAMESPACE, b"message"),
                )
            });
            let keys: Vec<_> = (0..17)
                .map(|i| Lazy::<VerifyingKey>::deferred(&mut fixtures[i % 3].0.as_ref(), ()))
                .collect();
            for _ in 0..2 {
                let mut batch = BatchVerifier::new(keys.len() * 2);
                for (i, key) in keys.iter().enumerate() {
                    let (public_key, signature) = &fixtures[(i + 1) % 3];
                    batch.add(NAMESPACE, b"message", public_key, signature);
                    batch.add_lazy(NAMESPACE, b"message", key, &fixtures[i % 3].1);
                }
                batch.add(NAMESPACE, b"message", &fixtures[0].0, &fixtures[0].1);
                assert!(batch.verify(&mut test_rng(), strategy));
                for (i, key) in keys.iter().enumerate() {
                    let public_key = &fixtures[i % 3].0;
                    assert_eq!(key.get_cached(), Some(Some(public_key)));
                    assert_eq!(key.get(), Some(public_key));
                }
            }
        }
        run(&Sequential);
        run(&Rayon::new(NZUsize!(4)).unwrap());
    }

    #[test]
    fn lazy_batch_caches_malformed_points_and_rejects_wrong_lengths() {
        const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_LAZY_INVALID_TEST";
        let signing_key = SigningKey::from_seed([42; 32]);
        let public_key = signing_key.verifying_key();
        let signature = signing_key.sign(NAMESPACE, b"message");
        let mut malformed = [0u8; 32];
        malformed[0] = 2;
        let keys: Vec<_> = (0..17)
            .map(|_| Lazy::<VerifyingKey>::deferred(&mut malformed.as_slice(), ()))
            .collect();
        for _ in 0..2 {
            let mut batch = BatchVerifier::new(keys.len());
            for key in &keys {
                batch.add_lazy(NAMESPACE, b"message", key, &signature);
            }
            assert!(!batch.verify(&mut test_rng(), &Sequential));
            for key in &keys {
                assert_eq!(key.get_cached(), Some(None));
                assert!(key.get().is_none());
            }
        }

        for size in [0, 31, 33, 64] {
            let bytes = vec![0u8; size];
            let key = Lazy::<VerifyingKey>::deferred(&mut bytes.as_slice(), ());
            let mut batch = BatchVerifier::new(2);
            batch.add(NAMESPACE, b"message", &public_key, &signature);
            batch.add_lazy(NAMESPACE, b"message", &key, &signature);
            assert!(!batch.verify(&mut test_rng(), &Sequential));
        }
    }

    #[test]
    fn signature_is_bound_to_namespace() {
        const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST";
        const WRONG_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST_WRONG";

        let signing_key = SigningKey::from_seed([42; 32]);
        let verifying_key = signing_key.verifying_key();
        let message = b"message";
        let signature = signing_key.sign(NAMESPACE, message);

        assert!(verifying_key.verify(NAMESPACE, message, &signature));
        assert!(!verifying_key.verify(WRONG_NAMESPACE, message, &signature));
    }

    #[test]
    fn signing_key_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<SigningKey>();
        assert!(core::mem::needs_drop::<SigningKey>());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::{Signature, SigningKey, VerifyingKey};
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<SigningKey> => 1024,
            CodecConformance<VerifyingKey>,
            CodecConformance<Signature>,
        }
    }
}
