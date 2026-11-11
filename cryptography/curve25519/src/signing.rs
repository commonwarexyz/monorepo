//! Ed25519 signing keys, signatures, and verification.
//!
//! # Validation criteria (ZIP215)
//!
//! Signature validation follows [ZIP215], the criteria that make Ed25519 safe for consensus:
//!
//! - The point encodings of the public key `A` and the signature component `R` are accepted
//!   even when non-canonical (a `y` coordinate at or above `p`, or a negative-zero `x`), as long
//!   as they decode to a curve point.
//! - The scalar component `s` must be canonical (`s < L`), ruling out signature malleability.
//! - The verification equation is cofactored: `[8](s*B - R - H(R || A || M)*A) == identity`.
//!
//! A [`PublicKey`] or [`Signature`] runs the point and scalar checks when it is built from its
//! encoding and keeps the decoded point, so verification checks only the equation. Single and
//! batch verification apply the same criteria. A non-empty batch of at most `u32::MAX`
//! signatures is always accepted when every signature verifies individually. Because batch
//! verification checks a randomized linear combination, an invalid batch may be accepted with
//! probability about `2^-128`, provided each verification call draws a fresh seed from an RNG
//! unpredictable to whoever assembled the batch. See [this post] for why these criteria matter.
//!
//! [this post]: https://hdevalence.ca/blog/2020-10-04-its-25519am
//! [ZIP215]: https://zips.z.cash/zip-0215

mod core;

use self::core::Scalar;
use crate::curve::{G, GAffine};
use ::core::{
    cmp::Ordering,
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::BufMut;
use commonware_codec::{Buf, FixedSize, Read, Write};
use commonware_cryptography::{
    BatchEntry, BatchVerifier, Encoding, Malformed, Signer, Validated, Verifier,
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

/// Splits a signature encoding into the encodings of `R` and `s`.
const fn halves(bytes: &[u8; 64]) -> (&[u8; 32], &[u8; 32]) {
    let halves = bytes.as_chunks::<32>().0;
    (&halves[0], &halves[1])
}

/// An Ed25519 signing key.
///
/// Secret material is zeroized when the key is dropped.
/// Serialization writes the raw secret seed, so callers must protect the encoded bytes as
/// secret key material.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SigningKey {
    /// When serializing, we want to just write the seed, so we keep it around.
    seed: [u8; 32],
    /// The private prefix we use to derive a deterministic nonce for each message.
    prefix: [u8; 32],
    /// The pruned secret scalar, reduced modulo the basepoint order.
    scalar: Scalar,
    /// The public key derived from the secret scalar.
    #[zeroize(skip)]
    public_key: PublicKey,
}

impl SigningKey {
    fn from_seed(seed: &[u8; 32]) -> Self {
        // Following: https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5.
        // The first half becomes our secret scalar material, while the second half
        // is the private prefix we use to derive deterministic nonces.
        let mut h = Zeroizing::new([0u8; 64]);
        FixedOutput::finalize_into(sha2::Sha512::new().chain(seed), (&mut *h).into());
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

        // The key keeps its point in affine form (see `PublicKey::point`).
        let point = G::mul_base_secret(&scalar_le_bytes).to_affine();
        let public_key = PublicKey {
            bytes: point.compress(),
            point,
        };

        Self {
            seed: *seed,
            prefix: *prefix,
            scalar: *scalar,
            public_key,
        }
    }

    fn sign_message(&self, msg: &[u8]) -> Signature {
        let mut nonce_digest = Zeroizing::new([0u8; 64]);
        FixedOutput::finalize_into(
            sha2::Sha512::new().chain(self.prefix.as_slice()).chain(msg),
            (&mut *nonce_digest).into(),
        );
        let nonce = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&nonce_digest));
        let nonce_bytes = Zeroizing::new(nonce.to_bytes());

        // The signature keeps `R` in affine form, as a key does its point, since its projective
        // coordinates depend on the nonce.
        let r = G::mul_base_secret(&nonce_bytes).to_affine();
        let r_bytes = r.compress();

        let challenge_digest: [u8; 64] = sha2::Sha512::new()
            .chain(r_bytes)
            .chain(self.public_key.bytes)
            .chain(msg)
            .finalize_fixed()
            .into();
        let challenge = Scalar::from_bytes_mod_order_wide(&challenge_digest);
        let challenge_scalar = Zeroizing::new(challenge.mul_mod_l(&self.scalar));
        let s = nonce.add_mod_l(&challenge_scalar);

        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&r_bytes);
        bytes[32..].copy_from_slice(&s.to_bytes());
        Signature { bytes, r, s }
    }

    /// The public key associated with this signing key.
    ///
    /// Signatures produced by this signing key can be verified using this key.
    pub fn public_key(&self) -> PublicKey {
        self.public_key.clone()
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

impl commonware_cryptography::PrivateKey for SigningKey {}

impl Signer for SigningKey {
    type Signature = Signature;
    type PublicKey = PublicKey;

    fn public_key(&self) -> PublicKey {
        Self::public_key(self)
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Signature {
        Self::sign(self, namespace, msg)
    }
}

impl Random for SigningKey {
    fn random(mut rng: impl rand_core::CryptoRng) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut seed[..]);
        Self::from_seed(&seed)
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

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let mut seed = Zeroizing::new([0u8; Self::SIZE]);
        buf.try_copy_to_slice(&mut seed[..])
            .map_err(|_| commonware_codec::Error::EndOfBuffer)?;
        Ok(Self::from_seed(&seed))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for SigningKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let seed: Zeroizing<[u8; Self::SIZE]> = Zeroizing::new(u.arbitrary()?);
        Ok(Self::from_seed(&seed))
    }
}

/// The encoding of an Ed25519 public key.
pub type PublicKeyBytes = Encoding<PublicKey, 32>;

/// An Ed25519 public key.
///
/// A key is built from its [`PublicKeyBytes`], which must encode a curve point. As ZIP215
/// requires, non-canonical encodings and points of small order are accepted. The key keeps the
/// decoded point, so verification never decompresses a key, and [`Validated::try_from_batch`]
/// decompresses many keys together, lane-wise.
///
/// Equality, ordering, and hashing use the original encoding. Distinct encodings of the same
/// point are distinct keys, and verification hashes the received bytes as ZIP215 requires.
#[derive(Clone)]
pub struct PublicKey {
    /// The key's encoding, hashed into every challenge.
    bytes: [u8; 32],
    /// The point `bytes` encodes, in affine coordinates.
    ///
    /// The projective coordinates of a secret scalar multiplication depend on the scalar as well
    /// as the point. This type is cloned freely and never zeroized, so it keeps the point in
    /// affine form.
    point: GAffine,
}

impl PublicKey {
    /// Verifies `sig` over the namespaced message, per the [module's validation
    /// criteria](self).
    ///
    /// # Panics
    ///
    /// Panics if `namespace` is longer than `u32::MAX` bytes.
    #[must_use]
    pub fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Signature) -> bool {
        let msg = union_unique(namespace, msg);
        core::verify(self, sig, &msg)
    }

    /// Verifies an unframed message for raw Ed25519 test-vector checks.
    #[cfg(test)]
    pub(crate) fn verify_raw(&self, msg: &[u8], sig: &Signature) -> bool {
        core::verify(self, sig, msg)
    }

    /// Batch-verifies unframed messages for raw Ed25519 test-vector checks.
    #[cfg(test)]
    pub(crate) fn verify_batch_raw(
        rng: &mut impl CryptoRng,
        items: &[(&Self, &Signature, &[u8])],
        strategy: &impl Strategy,
    ) -> bool {
        let items: Vec<_> = items
            .iter()
            .map(|&(key, signature, message)| core::Item {
                key,
                signature,
                namespace: None,
                message,
            })
            .collect();
        core::verify_batch(rng, &items, strategy)
    }
}

impl TryFrom<PublicKeyBytes> for PublicKey {
    type Error = Malformed;

    fn try_from(bytes: PublicKeyBytes) -> Result<Self, Malformed> {
        let bytes = *bytes.as_array();
        let point = GAffine::decompress(&bytes).ok_or(Malformed)?;
        Ok(Self { bytes, point })
    }
}

impl From<PublicKey> for PublicKeyBytes {
    fn from(key: PublicKey) -> Self {
        Self::new(key.bytes)
    }
}

impl Validated for PublicKey {
    type Bytes = PublicKeyBytes;

    /// Decompresses the keys together, lane-wise, across `strategy`.
    fn try_from_batch(bytes: &[PublicKeyBytes], strategy: &impl Strategy) -> Vec<Option<Self>> {
        core::decompress_many(bytes.len(), |i| *bytes[i].as_array(), strategy)
            .into_iter()
            .zip(bytes)
            .map(|(point, bytes)| {
                point.map(|point| Self {
                    bytes: *bytes.as_array(),
                    point,
                })
            })
            .collect()
    }
}

impl commonware_cryptography::PublicKey for PublicKey {}

impl Verifier for PublicKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Signature) -> bool {
        Self::verify(self, namespace, msg, sig)
    }
}

impl BatchVerifier for PublicKey {
    /// Checks all the signatures projected from `items`, per the [module's validation
    /// criteria](self). The projection receives each item's index in `items` and must return the
    /// same entry for a given index and item. A signer reused across the batch contributes one
    /// term to the batch equation for all of its signatures.
    ///
    /// Empty batches and batches containing more than `u32::MAX` signatures are rejected. Within
    /// that limit, a non-empty batch is always accepted when every signature verifies individually.
    /// Because this checks a randomized linear combination, an invalid batch may be accepted when
    /// the random weights make the combined equation hold, an event of negligible probability
    /// (about `2^-128`).
    ///
    /// This bound requires an RNG unpredictable to whoever assembled the batch. A predictable
    /// `rng` lets an attacker construct an invalid batch that passes verification.
    ///
    /// Rejecting an invalid batch can cost as much as accepting a valid batch of the same size.
    /// Bound the number of signatures and the size of messages taken from untrusted sources.
    ///
    /// # Panics
    ///
    /// Panics if a namespace is longer than `u32::MAX` bytes.
    fn verify_batch<'a, R, T, F>(
        rng: &mut R,
        items: &'a [T],
        project: F,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        T: Sync,
        F: Fn(usize, &'a T) -> BatchEntry<'a, Self> + Sync,
    {
        // Sorting and grouping use compact indices, so the limit is enforced before any item is
        // projected or stored: a slice of zero-sized items can be far longer than the vector of
        // projected items it would otherwise allocate.
        if items.is_empty() || u32::try_from(items.len()).is_err() {
            return false;
        }
        let items: Vec<_> = items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let entry = project(i, item);
                core::Item {
                    key: entry.public_key,
                    signature: entry.signature,
                    namespace: Some(entry.namespace),
                    message: entry.message,
                }
            })
            .collect();
        core::verify_batch(rng, &items, strategy)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Hex(&self.bytes))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for PublicKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for PublicKey {
    fn write(&self, buf: &mut impl BufMut) {
        self.bytes.write(buf);
    }
}

impl FixedSize for PublicKey {
    const SIZE: usize = 32;
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for PublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(SigningKey::arbitrary(u)?.public_key())
    }
}

/// The encoding of an Ed25519 signature.
pub type SignatureBytes = Encoding<Signature, 64>;

/// An Ed25519 signature.
///
/// A signature is built from its [`SignatureBytes`], which must encode a curve point `R`,
/// accepted from any encoding as ZIP215 requires, and a scalar `s` below the group order. The
/// signature keeps both decoded, so verification checks only the equation, and
/// [`Validated::try_from_batch`] decompresses the `R` points of many signatures together,
/// lane-wise.
///
/// For an honestly generated [`PublicKey`], successful verification demonstrates approval by the
/// holder of the corresponding [`SigningKey`]. A maliciously generated public key can admit a
/// signature that verifies for any message.
///
/// Equality, ordering, and hashing compare the original encoding.
#[derive(Clone)]
pub struct Signature {
    /// The encoding `R || s`, whose `R` half is hashed into the challenge.
    bytes: [u8; 64],
    /// The point the first half of `bytes` encodes.
    r: GAffine,
    /// The scalar the second half of `bytes` encodes.
    s: Scalar,
}

impl Signature {
    /// The encoding of `R`.
    const fn r_bytes(&self) -> &[u8; 32] {
        halves(&self.bytes).0
    }
}

impl TryFrom<SignatureBytes> for Signature {
    type Error = Malformed;

    fn try_from(bytes: SignatureBytes) -> Result<Self, Malformed> {
        let bytes = *bytes.as_array();
        let (r, s) = halves(&bytes);
        let r = GAffine::decompress(r).ok_or(Malformed)?;
        let s = Scalar::from_canonical_bytes(s).ok_or(Malformed)?;
        Ok(Self { bytes, r, s })
    }
}

impl From<Signature> for SignatureBytes {
    fn from(signature: Signature) -> Self {
        Self::new(signature.bytes)
    }
}

impl Validated for Signature {
    type Bytes = SignatureBytes;

    /// Decompresses the signatures' `R` points together, lane-wise, across `strategy`.
    fn try_from_batch(bytes: &[SignatureBytes], strategy: &impl Strategy) -> Vec<Option<Self>> {
        core::decompress_many(bytes.len(), |i| *halves(bytes[i].as_array()).0, strategy)
            .into_iter()
            .zip(bytes)
            .map(|(r, bytes)| {
                let bytes = *bytes.as_array();
                let s = Scalar::from_canonical_bytes(halves(&bytes).1)?;
                Some(Self { bytes, r: r?, s })
            })
            .collect()
    }
}

impl commonware_cryptography::Signature for Signature {}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Signature {}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
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

impl Deref for Signature {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
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

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signing_key = SigningKey::arbitrary(u)?;
        let message: Vec<u8> = u.arbitrary()?;
        Ok(signing_key.sign(&[], &message))
    }
}

#[cfg(test)]
mod tests {
    use super::{PublicKey, PublicKeyBytes, Signature, SignatureBytes, SigningKey};
    use crate::curve::{GAffine, LANES};
    use commonware_cryptography::{
        BatchEntry, BatchVerifier as _, PrivateKey, Validated as _, Verifier,
    };
    use commonware_parallel::{Sequential, mocks::explore};
    use commonware_utils::test_rng;
    use core::cmp::Ordering;
    use std::collections::HashSet;

    /// Returns `signature` with the lowest bit of `s` flipped. Only `s = L - 1` would become
    /// non-canonical.
    fn flip_s(signature: &Signature) -> Signature {
        let mut bytes = signature.bytes;
        bytes[32] ^= 1;
        Signature::try_from(SignatureBytes::new(bytes)).unwrap()
    }

    #[test]
    fn batch_entries_use_union_unique_framing() {
        // Signing frames each message with `union_unique`. The pairs include an empty namespace
        // and message, and a 200-byte namespace whose length prefix takes two bytes.
        let signer = SigningKey::from_seed(&[3; 32]);
        let key = signer.public_key();
        let pairs = [
            (&b""[..], &b""[..]),
            (b"ns", b"message"),
            (&[7; 200][..], b"m"),
        ];
        let signed: Vec<_> = pairs
            .iter()
            .map(|&(namespace, message)| (namespace, message, signer.sign(namespace, message)))
            .collect();
        let verify = |entries: &[(&[u8], &[u8], Signature)]| {
            PublicKey::verify_batch(
                &mut test_rng(),
                entries,
                |_, (namespace, message, signature)| BatchEntry {
                    namespace,
                    message,
                    public_key: &key,
                    signature,
                },
                &Sequential,
            )
        };
        assert!(verify(&signed));

        // Moving bytes from the message into the namespace changes the framed message.
        let (_, _, signature) = signed[1].clone();
        assert!(!verify(&[(&b"nsm"[..], &b"essage"[..], signature)]));
    }

    /// Equality, ordering, and hashing follow the encoding, so a key built from its encoding
    /// equals the key it was derived from, and two encodings of the same point stay distinct keys.
    #[test]
    fn public_key_identity_follows_encoding() {
        let key = <SigningKey as commonware_math::algebra::Random>::random(test_rng()).public_key();
        let converted = PublicKey::try_from(PublicKeyBytes::from(key.clone())).unwrap();
        assert_eq!(key.point.compress(), converted.point.compress());
        assert_eq!(key, converted);
        assert_eq!(key.cmp(&converted), Ordering::Equal);
        assert!(!HashSet::from([key]).insert(converted));

        // `y = 1` and the non-canonical `y = p + 1` both encode the identity.
        let mut canonical = [0u8; 32];
        canonical[0] = 1;
        let mut noncanonical = [0xffu8; 32];
        noncanonical[0] = 0xee;
        noncanonical[31] = 0x7f;
        let canonical = PublicKey::try_from(PublicKeyBytes::new(canonical)).unwrap();
        let noncanonical = PublicKey::try_from(PublicKeyBytes::new(noncanonical)).unwrap();
        assert_eq!(canonical.point.compress(), noncanonical.point.compress());
        assert_ne!(canonical, noncanonical);
        assert_ne!(canonical.cmp(&noncanonical), Ordering::Equal);
        assert!(HashSet::from([canonical]).insert(noncanonical));
    }

    #[test]
    fn empty_batch_is_invalid() {
        let empty: [(); 0] = [];
        assert!(!PublicKey::verify_batch(
            &mut test_rng(),
            &empty,
            |_, _| unreachable!(),
            &Sequential
        ));
    }

    /// A slice longer than the batch limit is rejected before its items are projected. Zero-sized
    /// items make such a slice cheap to build, while the projected items would not be.
    #[test]
    fn oversized_batch_is_invalid() {
        let signer = SigningKey::from_seed(&[9; 32]);
        let key = signer.public_key();
        let signature = signer.sign(b"namespace", b"message");
        let items = vec![(); usize::MAX];
        assert!(!PublicKey::verify_batch(
            &mut test_rng(),
            &items,
            |_, _| BatchEntry {
                namespace: b"namespace",
                message: b"message",
                public_key: &key,
                signature: &signature,
            },
            &Sequential
        ));
    }

    #[test]
    fn signature_is_bound_to_namespace() {
        const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST";
        const WRONG_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST_WRONG";

        let signing_key = SigningKey::from_seed(&[42; 32]);
        let public_key = signing_key.public_key();
        let message = b"message";
        let signature = signing_key.sign(NAMESPACE, message);

        assert!(public_key.verify(NAMESPACE, message, &signature));
        assert!(!public_key.verify(WRONG_NAMESPACE, message, &signature));
    }

    /// Signing and verifying through the `commonware-cryptography` traits match the inherent
    /// methods, and a signature keeps the decoded `R` and `s` it was built from.
    #[test]
    fn sign_and_verify() {
        fn sign<S: PrivateKey>(
            signer: &S,
            namespace: &[u8],
            msg: &[u8],
        ) -> (S::PublicKey, S::Signature) {
            (signer.public_key(), signer.sign(namespace, msg))
        }

        let signing_key = SigningKey::from_seed(&[5; 32]);
        let (public_key, signature) = sign(&signing_key, b"namespace", b"message");
        assert_eq!(public_key, signing_key.public_key());
        assert_eq!(signature, signing_key.sign(b"namespace", b"message"));
        let converted = Signature::try_from(SignatureBytes::from(signature.clone())).unwrap();
        assert_eq!(converted.r.compress(), signature.r.compress());
        assert_eq!(converted.s.to_bytes(), signature.s.to_bytes());
        assert!(Verifier::verify(
            &public_key,
            b"namespace",
            b"message",
            &signature
        ));
        assert!(!Verifier::verify(
            &public_key,
            b"other",
            b"message",
            &signature
        ));
        assert!(!public_key.verify(b"namespace", b"message", &flip_s(&signature)));

        // The batch path rejects a signature over another namespace, an altered scalar, an
        // empty batch, and an oversized batch.
        let batch = |records: &[(&[u8], &[u8], Signature)]| {
            PublicKey::verify_batch(
                &mut test_rng(),
                records,
                |_, (namespace, message, signature)| BatchEntry {
                    namespace,
                    message,
                    public_key: &public_key,
                    signature,
                },
                &Sequential,
            )
        };
        assert!(batch(&[(b"namespace", b"message", signature.clone())]));
        assert!(!batch(&[
            (b"namespace", b"message", signature.clone()),
            (b"other", b"message", signature.clone()),
        ]));
        assert!(!batch(&[
            (b"namespace", b"message", signature.clone()),
            (b"namespace", b"message", flip_s(&signature)),
        ]));
        assert!(!batch(&[]));
        let oversized = vec![(); usize::MAX];
        assert!(!PublicKey::verify_batch(
            &mut test_rng(),
            &oversized,
            |_, _| BatchEntry {
                namespace: b"namespace",
                message: b"message",
                public_key: &public_key,
                signature: &signature,
            },
            &Sequential,
        ));
    }

    /// [`PublicKey`] and [`Signature`] meet the validation contract of the cryptography traits,
    /// and a key accepts every encoding of a curve point, including the non-canonical and
    /// small-order encodings ZIP215 admits, keeping its bytes and the point they encode.
    #[test]
    fn validation_contract() {
        // `y = 2` is not the `y` coordinate of any curve point, with either sign bit.
        let mut non_point = [0u8; 32];
        non_point[0] = 2;
        let mut non_point_negative = non_point;
        non_point_negative[31] |= 0x80;
        commonware_cryptography::assert_validation_contract::<SigningKey>(
            &[&non_point, &non_point_negative],
            |honest| {
                // The honest signature with a non-point `R` or with `s + L` in place of `s`.
                // Adding `L` encodes the same scalar non-canonically.
                let mut s_plus_l = honest.to_vec();
                let mut carry = 0u16;
                for (byte, l) in s_plus_l[32..].iter_mut().zip(crate::test::SCALAR_ORDER) {
                    let [low, high] = (u16::from(*byte) + u16::from(l) + carry).to_le_bytes();
                    *byte = low;
                    carry = u16::from(high);
                }
                let mut r_non_point = honest.to_vec();
                r_non_point[..32].copy_from_slice(&non_point);
                vec![s_plus_l, r_non_point]
            },
        );

        for encoding in crate::test::ZIP215_POINTS {
            let key = PublicKey::try_from(PublicKeyBytes::new(encoding)).unwrap();
            assert_eq!(key.as_ref(), encoding);
            assert_eq!(
                key.point.compress(),
                GAffine::decompress(&encoding).unwrap().compress()
            );
            assert_eq!(PublicKeyBytes::from(key).as_array(), &encoding);
        }
    }

    /// Converting many encodings together agrees with converting each alone under every strategy,
    /// at counts on both sides of a lane boundary, with malformed encodings anywhere in the
    /// batch.
    #[test]
    fn batch_conversion_agrees_with_single() {
        // Keys of three signers, every ZIP215 point, and a non-point encoding, in a repeating
        // pattern so that each kind lands in every lane of a unit.
        let signers: Vec<SigningKey> = (0..3).map(|i| SigningKey::from_seed(&[i; 32])).collect();
        let mut non_point = [0u8; 32];
        non_point[0] = 2;
        let mut key_bytes: Vec<PublicKeyBytes> = Vec::new();
        for i in 0..3 * LANES + 1 {
            let bytes = match i % 5 {
                0..=2 => *PublicKeyBytes::from(signers[i % 3].public_key()).as_array(),
                3 => crate::test::ZIP215_POINTS[i % crate::test::ZIP215_POINTS.len()],
                _ => non_point,
            };
            key_bytes.push(PublicKeyBytes::new(bytes));
        }

        // Honest signatures, signatures with `R` a ZIP215 point and `s = 0`, and malformed
        // signatures with a non-point `R` or a non-canonical `s`.
        let mut signature_bytes: Vec<SignatureBytes> = Vec::new();
        for i in 0..3 * LANES + 1 {
            let mut bytes =
                *SignatureBytes::from(signers[i % 3].sign(b"namespace", &i.to_le_bytes()))
                    .as_array();
            match i % 5 {
                0..=1 => {}
                2 => {
                    bytes[..32].copy_from_slice(
                        &crate::test::ZIP215_POINTS[i % crate::test::ZIP215_POINTS.len()],
                    );
                    bytes[32..].fill(0);
                }
                3 => bytes[..32].copy_from_slice(&non_point),
                _ => bytes[32..].copy_from_slice(&crate::test::SCALAR_ORDER),
            }
            signature_bytes.push(SignatureBytes::new(bytes));
        }

        for count in [0, 1, LANES - 1, LANES, LANES + 1, 2 * LANES, 3 * LANES + 1] {
            let keys = explore(|strategy| {
                PublicKey::try_from_batch(&key_bytes[..count], strategy)
                    .into_iter()
                    .map(|key| key.map(|key| (key.bytes, key.point.compress())))
                    .collect::<Vec<_>>()
            });
            let expected: Vec<_> = key_bytes[..count]
                .iter()
                .map(|bytes| {
                    PublicKey::try_from(bytes.clone())
                        .ok()
                        .map(|key| (key.bytes, key.point.compress()))
                })
                .collect();
            assert_eq!(keys, expected, "count {count}");
            assert!(count < 5 || keys.iter().any(Option::is_none));

            let signatures = explore(|strategy| {
                Signature::try_from_batch(&signature_bytes[..count], strategy)
                    .into_iter()
                    .map(|signature| {
                        signature.map(|signature| {
                            (
                                signature.bytes,
                                signature.r.compress(),
                                signature.s.to_bytes(),
                            )
                        })
                    })
                    .collect::<Vec<_>>()
            });
            let expected: Vec<_> = signature_bytes[..count]
                .iter()
                .map(|bytes| {
                    Signature::try_from(bytes.clone()).ok().map(|signature| {
                        (
                            signature.bytes,
                            signature.r.compress(),
                            signature.s.to_bytes(),
                        )
                    })
                })
                .collect();
            assert_eq!(signatures, expected, "count {count}");
            assert!(count < 4 || signatures.iter().any(Option::is_none));
        }
    }

    #[test]
    fn signing_key_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<SigningKey>();
        assert!(core::mem::needs_drop::<SigningKey>());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::{PublicKeyBytes, SignatureBytes, SigningKey};
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<SigningKey> => 1024,
            CodecConformance<PublicKeyBytes>,
            CodecConformance<SignatureBytes>,
        }
    }
}
