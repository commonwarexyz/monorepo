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
use crate::{
    STACK_SCRUB_BYTES,
    curve::{G, GAffine},
};
use ::core::{
    fmt::{self, Debug, Display},
    hash::{Hash, Hasher},
    ops::Deref,
};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing, zeroize_stack};

/// An Ed25519 signing key.
///
/// The secret material lives in one heap allocation that is zeroized when the key is dropped, so
/// a move copies only a pointer, and key derivation and signing clear the stack they used before
/// returning, within the limits described in the [crate documentation](crate#zeroization).
/// Serialization writes the raw secret seed, so callers must protect the encoded bytes as secret
/// key material.
pub struct SigningKey {
    secret: Box<Secret>,
    /// The verifying key derived from the secret scalar.
    verifying_key: VerifyingKey,
}

/// The secret half of a [`SigningKey`].
#[derive(Zeroize, ZeroizeOnDrop)]
struct Secret {
    /// When serializing, we want to just write the seed, so we keep it around.
    seed: [u8; 32],
    /// The private prefix we use to derive a deterministic nonce for each message.
    prefix: [u8; 32],
    /// The pruned secret scalar, reduced modulo the basepoint order.
    scalar: Scalar,
}

impl Secret {
    const ZERO: Self = Self {
        seed: [0; 32],
        prefix: [0; 32],
        scalar: Scalar::ZERO,
    };
}

// The boxed `Secret` zeroizes itself when the key drops it.
impl ZeroizeOnDrop for SigningKey {}

impl Clone for SigningKey {
    fn clone(&self) -> Self {
        // Fill a fresh allocation field by field: cloning the whole `Secret` would build it on
        // the stack before moving it to the heap.
        let mut secret = Box::new(Secret::ZERO);
        secret.seed.copy_from_slice(&self.secret.seed);
        secret.prefix.copy_from_slice(&self.secret.prefix);
        secret.scalar = self.secret.scalar;
        Self {
            secret,
            verifying_key: self.verifying_key.clone(),
        }
    }
}

impl SigningKey {
    /// Derives the key of `seed`, then clears the stack that derivation used.
    fn from_seed(seed: &[u8; 32]) -> Self {
        let key = Self::derive(seed);
        zeroize_stack::<STACK_SCRUB_BYTES>();
        key
    }

    /// The derivation itself, kept out of line so that [`Self::from_seed`] can clear its frames.
    #[inline(never)]
    fn derive(seed: &[u8; 32]) -> Self {
        let mut secret = Box::new(Secret::ZERO);
        secret.seed.copy_from_slice(seed);
        // Following: https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5.
        // The first half becomes our secret scalar material, while the second half
        // is the private prefix we use to derive deterministic nonces.
        let mut h = Zeroizing::new([0u8; 64]);
        FixedOutput::finalize_into(sha2::Sha512::new().chain(seed), (&mut *h).into());
        let mut scalar_le_bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(h[..32].try_into().expect("h is 64 bytes"));
        secret.prefix.copy_from_slice(&h[32..]);
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
        secret.scalar = Scalar::from_bytes_mod_order_wide(&wide_scalar);

        // Normalize before caching (see `VerifyingKey::point`).
        let point = G::mul_base_secret(&scalar_le_bytes).to_affine();
        let verifying_key = VerifyingKey {
            bytes: core::VerifyingKeyBytes::new(point.compress()),
            point: Some(point.to_extended()),
        };

        Self {
            secret,
            verifying_key,
        }
    }

    /// Signs an unframed message, kept out of line so that callers can clear its frames.
    #[inline(never)]
    fn sign_message(&self, msg: &[u8]) -> Signature {
        let mut nonce_digest = Zeroizing::new([0u8; 64]);
        FixedOutput::finalize_into(
            sha2::Sha512::new()
                .chain(self.secret.prefix.as_slice())
                .chain(msg),
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
        let challenge_scalar = Zeroizing::new(challenge.mul_mod_l(&self.secret.scalar));
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
    /// is consumed. The stack that signing used is cleared before returning, within the limits
    /// described in the [crate documentation](crate#zeroization).
    ///
    /// # Panics
    ///
    /// Panics if `namespace` is longer than `u32::MAX` bytes.
    ///
    /// [RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
    pub fn sign(&self, namespace: &[u8], msg: &[u8]) -> Signature {
        let signature = self.sign_message(&union_unique(namespace, msg));
        zeroize_stack::<STACK_SCRUB_BYTES>();
        signature
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
        self.secret.seed.write(buf);
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
///
/// # Key validation
///
/// Verification follows ZIP215 and accepts keys of any order. A key of small order admits a
/// signature that verifies for every message, and the holder of a secret scalar can sign under
/// its honest key and the seven keys that differ from it by a torsion component, so distinct keys
/// outside the prime-order subgroup need not belong to distinct signers.
///
/// Callers that register keys from untrusted sources and need a nonidentity key of order `L`
/// should require `!is_small_order() && is_torsion_free()`: the first check rejects the keys
/// anyone can forge under, and the second rejects mixed-order keys. Keys produced by
/// [`SigningKey::verifying_key`] pass both checks.
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

    /// The point this key encodes, if its encoding is one.
    fn point(&self) -> Option<G> {
        self.point
            .or_else(|| GAffine::decompress(self.bytes.as_bytes()).map(GAffine::to_extended))
    }

    /// Returns whether this key is a point of small order (dividing 8), the identity included.
    ///
    /// A signature with `s = 0` and a small-order `R` verifies under such a key for every
    /// message. An encoding of no curve point is not of small order: it verifies no signature.
    pub fn is_small_order(&self) -> bool {
        self.point()
            .is_some_and(|point| point.mul_by_cofactor().is_identity())
    }

    /// Returns whether this key is a point of the prime-order subgroup (`[L]A` is the
    /// identity), the identity included.
    ///
    /// An encoding of no curve point is not in the subgroup. See [key
    /// validation](Self#key-validation) for how this combines with [`Self::is_small_order`].
    pub fn is_torsion_free(&self) -> bool {
        self.point()
            .is_some_and(|point| core::is_torsion_free(&point))
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
/// admit a signature that verifies for any message (see [`VerifyingKey::is_small_order`]).
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
    use super::{Scalar, Secret, Signature, SigningKey, VerifyingKey};
    use crate::curve::GAffine;
    use commonware_codec::{Copying, DecodeExt, Encode};
    use commonware_cryptography::{BatchEntry, BatchVerifier as _, PrivateKey, Verifier};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use core::cmp::Ordering;
    use std::collections::HashSet;
    use zeroize::Zeroize;

    /// An encoding of no curve point.
    fn undecodable() -> [u8; 32] {
        (2..=u8::MAX)
            .map(|y| {
                let mut encoding = [0; 32];
                encoding[0] = y;
                encoding
            })
            .find(|encoding| GAffine::decompress(encoding).is_none())
            .unwrap()
    }

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

    /// Derived keys have order `L`, the ZIP215 encodings are of small order with only the
    /// identity torsion free, a key with a torsion component is neither, and neither is an
    /// encoding of no point. The two kinds of key the checks reject each admit a signature the
    /// honest key does not.
    #[test]
    fn verifying_key_order_checks() {
        let signer = SigningKey::from_seed(&[9; 32]);
        let key = signer.verifying_key();
        let decoded = VerifyingKey::decode(key.encode()).unwrap();
        for honest in [&key, &decoded] {
            assert!(!honest.is_small_order());
            assert!(honest.is_torsion_free());
        }

        let mut torsion = None;
        let forged = Signature::decode(Copying(&[0u8; 64][..])).unwrap();
        for encoding in crate::test::ZIP215_POINTS {
            let key = VerifyingKey::decode(Copying(&encoding[..])).unwrap();
            let point = key.point().unwrap();
            assert!(key.is_small_order(), "{encoding:?}");
            assert_eq!(key.is_torsion_free(), point.is_identity(), "{encoding:?}");
            if !point.is_identity() {
                torsion = Some(point);
            }

            // Under a small-order key, a signature with `s = 0` and a small-order `R` verifies
            // any message.
            assert!(key.verify(b"ns", b"any message", &forged), "{encoding:?}");
        }
        assert!(!key.verify(b"ns", b"any message", &forged));

        // The holder of the secret scalar signs under the key with a torsion component added,
        // and that key verifies the signature while the honest key does not.
        let mixed_point = key.point().unwrap().add(torsion.unwrap());
        let mixed = VerifyingKey::decode(Copying(&mixed_point.compress()[..])).unwrap();
        assert!(!mixed.is_small_order());
        assert!(!mixed.is_torsion_free());
        let mut mixed_signer = signer;
        mixed_signer.verifying_key = mixed.clone();
        let signature = mixed_signer.sign(b"ns", b"message");
        assert!(mixed.verify(b"ns", b"message", &signature));
        assert!(!key.verify(b"ns", b"message", &signature));

        let no_point = VerifyingKey::decode(Copying(&undecodable()[..])).unwrap();
        assert!(!no_point.is_small_order());
        assert!(!no_point.is_torsion_free());
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

    /// A slice longer than the batch limit is rejected before its items are projected. Zero-sized
    /// items make such a slice cheap to build, while the projected items would not be.
    #[test]
    fn oversized_batch_is_invalid() {
        let signer = SigningKey::from_seed(&[9; 32]);
        let key = signer.verifying_key();
        let signature = signer.sign(b"namespace", b"message");
        let items = vec![(); usize::MAX];
        assert!(!VerifyingKey::verify_batch(
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
        assert_zeroize_on_drop::<Secret>();
        assert!(core::mem::needs_drop::<SigningKey>());
    }

    #[test]
    fn secret_zeroizes_every_field() {
        let mut secret = Secret {
            seed: [1; 32],
            prefix: [2; 32],
            scalar: Scalar::from_bytes_mod_order_wide(&[3; 64]),
        };
        secret.zeroize();
        assert_eq!(secret.seed, [0; 32]);
        assert_eq!(secret.prefix, [0; 32]);
        assert_eq!(secret.scalar.to_bytes(), [0; 32]);
    }

    /// Derivation and signing clear the dead stack they used: the probes find none of the
    /// secrets they handled, the scrub ran in every entry point, and it reaches below their
    /// deepest frame.
    #[cfg(all(not(debug_assertions), not(miri)))]
    mod stack {
        use super::super::{Scalar, SigningKey};
        use crate::{
            STACK_SCRUB_BYTES,
            test::stack::{contains, depth, probe, scrubbed, words_swapped},
        };
        use commonware_codec::{Copying, DecodeExt};
        use commonware_math::algebra::Random;
        use commonware_utils::{TestRng, union_unique};
        use rand_core::Rng;
        use sha2::{Digest, Sha512};

        /// Returns the 512-bit product of two little-endian 256-bit integers.
        fn product(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
            let mut out = [0u8; 64];
            for (i, &x) in a.iter().enumerate() {
                let mut carry = 0u32;
                for (j, &y) in b.iter().enumerate() {
                    let sum = u32::from(out[i + j]) + u32::from(x) * u32::from(y) + carry;
                    out[i + j] = sum as u8;
                    carry = sum >> 8;
                }
                out[i + 32] = carry as u8;
            }
            out
        }

        /// The key's secrets as derivation handles them: the seed, prefix, and scalar, and the
        /// seed and prefix as SHA-512 holds them.
        fn secrets(signer: &SigningKey) -> Vec<Vec<u8>> {
            let seed = signer.secret.seed;
            let prefix = signer.secret.prefix;
            vec![
                seed.to_vec(),
                prefix.to_vec(),
                signer.secret.scalar.to_bytes().to_vec(),
                words_swapped(&seed),
                words_swapped(&prefix),
            ]
        }

        fn assert_clear(span: &[u8], secrets: &[Vec<u8>]) {
            for (i, secret) in secrets.iter().enumerate() {
                assert!(!contains(span, secret), "secret {i} remains on the stack");
            }
            assert!(
                scrubbed(span, STACK_SCRUB_BYTES),
                "the operation did not scrub"
            );
        }

        #[test]
        fn derivation_leaves_no_secret_on_the_stack() {
            let seed = [7u8; 32];
            let (signer, span) = probe(|| SigningKey::from_seed(&seed));
            assert_clear(&span, &secrets(&signer));

            let (decoded, span) = probe(|| SigningKey::decode(Copying(&seed[..])).unwrap());
            assert_eq!(decoded.secret.seed, seed);
            assert_clear(&span, &secrets(&decoded));

            let mut rng = TestRng::new(3);
            let (random, span) = probe(|| SigningKey::random(&mut rng));
            let mut expected = [0u8; 32];
            TestRng::new(3).fill_bytes(&mut expected);
            assert_eq!(random.secret.seed, expected);
            assert_clear(&span, &secrets(&random));
        }

        #[test]
        fn signing_leaves_no_secret_on_the_stack() {
            let signer = SigningKey::from_seed(&[7; 32]);
            let (signature, span) = probe(|| signer.sign(b"ns", b"message"));

            // The nonce, the challenge's product with the scalar, and its reduction.
            let msg = union_unique(b"ns", b"message");
            let nonce_digest: [u8; 64] = Sha512::new()
                .chain_update(signer.secret.prefix)
                .chain_update(&msg)
                .finalize()
                .into();
            let nonce = Scalar::from_bytes_mod_order_wide(&nonce_digest);
            let challenge_digest: [u8; 64] = Sha512::new()
                .chain_update(&signature.bytes[..32])
                .chain_update(signer.verifying_key.as_ref())
                .chain_update(&msg)
                .finalize()
                .into();
            let challenge = Scalar::from_bytes_mod_order_wide(&challenge_digest);
            let scalar = signer.secret.scalar.to_bytes();
            let mut secrets = secrets(&signer);
            secrets.extend([
                nonce_digest.to_vec(),
                words_swapped(&nonce_digest),
                nonce.to_bytes().to_vec(),
                product(&challenge.to_bytes(), &scalar).to_vec(),
                challenge
                    .mul_mod_l(&signer.secret.scalar)
                    .to_bytes()
                    .to_vec(),
            ]);
            assert_clear(&span, &secrets);
        }

        #[test]
        fn scrub_covers_derivation_and_signing() {
            let seed = [7u8; 32];
            let reached = depth(&probe(|| SigningKey::derive(&seed)).1);
            assert!(
                reached <= STACK_SCRUB_BYTES,
                "derivation reached {reached} bytes below the caller"
            );

            let signer = SigningKey::from_seed(&seed);
            let msg = union_unique(b"ns", &[0x42; 200]);
            let reached = depth(&probe(|| signer.sign_message(&msg)).1);
            assert!(
                reached <= STACK_SCRUB_BYTES,
                "signing reached {reached} bytes below the caller"
            );
        }
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
