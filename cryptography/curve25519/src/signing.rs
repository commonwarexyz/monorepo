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
//! - The verification equation is cofactored: `[8](s*B - R - H(R || A || M)*A) == identity`.
//!
//! [`VerifyingKey::verify`] and [`VerifyingKey::verify_batch`] apply the same criteria.
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
use crate::curve::G;
use ::core::{
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::BufMut;
use commonware_codec::{Buf, FixedSize, Read, Write};
use commonware_cryptography::{BatchEntry, BatchVerifier, Signer, Verifier};
use commonware_formatting::Hex;
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_utils::{Array, Span, union_unique};
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
#[derive(Clone, ZeroizeOnDrop)]
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

        // Normalize before caching (see `VerifyingKey::point`).
        let point = G::mul_base_secret(&scalar_le_bytes).to_affine();
        let verifying_key = VerifyingKey {
            bytes: core::VerifyingKeyBytes::new(point.compress()),
            point: Some(point.to_extended()),
        };

        Self {
            seed: *seed,
            prefix: *prefix,
            scalar: *scalar,
            verifying_key,
        }
    }

    fn sign_message(&self, msg: &[u8]) -> Signature {
        let mut nonce_digest = Zeroizing::new([0u8; 64]);
        FixedOutput::finalize_into(
            sha2::Sha512::new().chain(self.prefix).chain(msg),
            (&mut *nonce_digest).into(),
        );
        let nonce = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&nonce_digest));
        let nonce_bytes = Zeroizing::new(nonce.to_bytes());
        let r_bytes = G::mul_base_secret(&nonce_bytes).compress();

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

impl commonware_cryptography::PrivateKey for SigningKey {}

impl Signer for SigningKey {
    type Signature = Signature;
    type PublicKey = VerifyingKey;

    fn public_key(&self) -> VerifyingKey {
        self.verifying_key()
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

/// A public key used to check signatures.
///
/// Decoding accepts any 32 bytes and defers point validation until signature verification.
/// Encodings that do not represent a curve point can never verify a signature.
/// Equality, ordering, and hashing use the original encoding: distinct encodings of the same
/// point are distinct keys, and verification hashes the received bytes as required by ZIP215.
#[derive(Clone)]
pub struct VerifyingKey {
    /// The encoded point.
    ///
    /// When deserializing, we just have the bytes, deferring parsing of them until
    /// signature verification, so that we can more efficiently parse them in batch.
    bytes: core::VerifyingKeyBytes,
    /// If available, the point associated with these bytes, normalized to `Z = 1`.
    ///
    /// The projective coordinates of a secret scalar multiplication depend on the scalar beyond
    /// the point itself, and this type is copied freely and never zeroized, so a cached point must
    /// carry only the point.
    point: Option<G>,
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

impl Deref for VerifyingKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
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

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            bytes: core::VerifyingKeyBytes::new(<[u8; Self::SIZE]>::read_cfg(buf, cfg)?),
            point: None,
        })
    }
}

impl Span for VerifyingKey {}

impl Array for VerifyingKey {}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for VerifyingKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            bytes: core::VerifyingKeyBytes::new(u.arbitrary()?),
            point: None,
        })
    }
}

impl VerifyingKey {
    fn verify_message(&self, msg: &[u8], sig: &Signature) -> bool {
        core::verify(
            &self.bytes,
            self.point.as_ref(),
            &core::Signature::from_bytes(sig.bytes),
            msg,
        )
    }

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

    /// Batch-verifies unframed messages for raw Ed25519 test-vector checks.
    #[cfg(test)]
    pub(crate) fn verify_batch_raw(
        rng: &mut impl CryptoRng,
        items: &[(&Self, &Signature, &[u8])],
        strategy: &impl Strategy,
    ) -> bool {
        let items: Vec<_> = items
            .iter()
            .map(|&(key, signature, message)| signature.batch_item(&key.bytes, None, message))
            .collect();
        core::verify_batch_bytes(rng, &items, strategy)
    }
}

impl commonware_cryptography::PublicKey for VerifyingKey {}

impl Verifier for VerifyingKey {
    type Signature = Signature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Signature) -> bool {
        Self::verify(self, namespace, msg, sig)
    }
}

impl BatchVerifier for VerifyingKey {
    /// Checks all the signatures projected from `items`, per the [module's validation
    /// criteria](self). The projection receives each item's index in `items` and must return the
    /// same entry for a given index and item.
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
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_cryptography::{BatchEntry, BatchVerifier as _};
    /// use commonware_cryptography_curve25519::signing::{SigningKey, VerifyingKey};
    /// use commonware_math::algebra::Random;
    /// use commonware_parallel::Sequential;
    /// use commonware_utils::test_rng;
    ///
    /// let key = SigningKey::random(test_rng());
    /// let verifying_key = key.verifying_key();
    /// let namespace = b"example";
    /// let records = [(b"message".as_slice(), key.sign(namespace, b"message"))];
    /// assert!(VerifyingKey::verify_batch(
    ///     &mut test_rng(),
    ///     &records,
    ///     |_, (message, signature)| BatchEntry {
    ///         namespace,
    ///         message,
    ///         public_key: &verifying_key,
    ///         signature,
    ///     },
    ///     &Sequential,
    /// ));
    /// ```
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
        let items: Vec<_> = items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let entry = project(i, item);
                entry.signature.batch_item(
                    &entry.public_key.bytes,
                    Some(entry.namespace),
                    entry.message,
                )
            })
            .collect();
        core::verify_batch_bytes(rng, &items, strategy)
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

impl Signature {
    /// Borrows this signature's `R` and `s` encodings with the signer's key and message as a
    /// batch item.
    const fn batch_item<'a>(
        &'a self,
        key: &'a core::VerifyingKeyBytes,
        namespace: Option<&'a [u8]>,
        message: &'a [u8],
    ) -> core::Item<'a> {
        let halves = self.bytes.as_chunks::<32>().0;
        core::Item {
            key,
            r: &halves[0],
            s: &halves[1],
            namespace,
            message,
        }
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

impl Read for Signature {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            bytes: <[u8; Self::SIZE]>::read_cfg(buf, cfg)?,
        })
    }
}

impl Span for Signature {}

impl Array for Signature {}

impl commonware_cryptography::Signature for Signature {}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            bytes: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{SigningKey, VerifyingKey};
    use commonware_codec::{Copying, DecodeExt, Encode};
    use commonware_cryptography::{BatchEntry, BatchVerifier as _, PrivateKey, Verifier};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use core::cmp::Ordering;
    use std::collections::HashSet;

    #[test]
    fn batch_entries_use_union_unique_framing() {
        // Signing frames each message with `union_unique`. The pairs include an empty namespace
        // and message, and a 200-byte namespace whose length prefix takes two bytes.
        let signer = SigningKey::from_seed(&[3; 32]);
        let key = signer.verifying_key();
        let pairs = [
            (&b""[..], &b""[..]),
            (b"ns", b"message"),
            (&[7; 200][..], b"m"),
        ];
        let signed: Vec<_> = pairs
            .iter()
            .map(|&(namespace, message)| (namespace, message, signer.sign(namespace, message)))
            .collect();
        let verify = |entries: &[(&[u8], &[u8], super::Signature)]| {
            VerifyingKey::verify_batch(
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

    /// Equality, ordering, and hashing follow the encoding: a decoded copy equals the original
    /// whatever its cached point, and two encodings of the same point stay distinct keys.
    #[test]
    fn verifying_key_identity_follows_encoding() {
        let key =
            <SigningKey as commonware_math::algebra::Random>::random(test_rng()).verifying_key();
        let decoded = VerifyingKey::decode(key.encode()).unwrap();
        assert!(key.point.is_some() && decoded.point.is_none());
        assert_eq!(key, decoded);
        assert_eq!(key.cmp(&decoded), Ordering::Equal);
        assert!(!HashSet::from([key]).insert(decoded));

        // `y = 1` and the non-canonical `y = p + 1` both encode the identity.
        let mut canonical = [0u8; 32];
        canonical[0] = 1;
        let mut noncanonical = [0xffu8; 32];
        noncanonical[0] = 0xee;
        noncanonical[31] = 0x7f;
        let point = |bytes| {
            crate::curve::GAffine::decompress(bytes)
                .unwrap()
                .to_extended()
        };
        assert_eq!(
            point(&canonical).compress(),
            point(&noncanonical).compress()
        );
        let canonical = VerifyingKey::decode(Copying(&canonical[..])).unwrap();
        let noncanonical = VerifyingKey::decode(Copying(&noncanonical[..])).unwrap();
        assert_ne!(canonical, noncanonical);
        assert_ne!(canonical.cmp(&noncanonical), Ordering::Equal);
        assert!(HashSet::from([canonical]).insert(noncanonical));
    }

    #[test]
    fn empty_batch_is_invalid() {
        let empty: [(); 0] = [];
        assert!(!VerifyingKey::verify_batch(
            &mut test_rng(),
            &empty,
            |_, _| unreachable!(),
            &Sequential
        ));
    }

    #[test]
    fn signature_is_bound_to_namespace() {
        const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST";
        const WRONG_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_CURVE25519_SIGNING_TEST_WRONG";

        let signing_key = SigningKey::from_seed(&[42; 32]);
        let verifying_key = signing_key.verifying_key();
        let message = b"message";
        let signature = signing_key.sign(NAMESPACE, message);

        assert!(verifying_key.verify(NAMESPACE, message, &signature));
        assert!(!verifying_key.verify(WRONG_NAMESPACE, message, &signature));
    }

    /// Signing and verifying through the `commonware-cryptography` traits match the inherent
    /// methods.
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
        let (verifying_key, signature) = sign(&signing_key, b"namespace", b"message");
        assert_eq!(verifying_key, signing_key.verifying_key());
        assert_eq!(signature, signing_key.sign(b"namespace", b"message"));
        assert!(Verifier::verify(
            &verifying_key,
            b"namespace",
            b"message",
            &signature
        ));
        assert!(!Verifier::verify(
            &verifying_key,
            b"other",
            b"message",
            &signature
        ));
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
